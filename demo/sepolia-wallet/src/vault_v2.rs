//! Fixed-size, authenticated v2 vault codec for the standalone Sepolia demo.
//!
//! The format is deliberately independent from both the demo v1 raw-key vault
//! and the production wallet vault. Every decoded account address is
//! recomputed from the decrypted secret before an opened value is returned.

#![cfg_attr(not(test), allow(dead_code))]

use core::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize as _, Zeroizing};

use crate::wallet_secret::{
    AccountMetadata, EthereumAddress, SecretError, WalletSecret, WalletSource,
};

const VAULT_MAGIC: &[u8; 8] = b"YWSPV002";
const PAYLOAD_MAGIC: &[u8; 8] = b"YWSPP002";
const VAULT_VERSION: u16 = 2;
const VAULT_HEADER_BYTES: usize = 112;
const VAULT_HEADER_BYTES_U16: u16 = 112;
const PAYLOAD_SCHEMA: u16 = 2;
const PASSWORD_PROFILE: u16 = 1;
const KDF_ARGON2ID: u16 = 1;
const AEAD_XCHACHA20_POLY1305: u16 = 1;
const ARGON2_MEMORY_KIB: u32 = 262_144;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const VAULT_ID_BYTES: usize = 16;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const PAYLOAD_BYTES: usize = 128;
const AEAD_TAG_BYTES: usize = 16;
const CIPHERTEXT_BYTES: usize = PAYLOAD_BYTES + AEAD_TAG_BYTES;
const VAULT_FILE_BYTES: usize = VAULT_HEADER_BYTES + CIPHERTEXT_BYTES;
const SEPOLIA_CHAIN_ID: u32 = 11_155_111;
const MINIMUM_PASSWORD_BYTES: usize = 12;
const MAXIMUM_PASSWORD_BYTES: usize = 1_024;
const LANGUAGE_RAW_SENTINEL: u8 = 0;
const LANGUAGE_ENGLISH: u8 = 1;
const DERIVATION_RAW_SENTINEL: u8 = 0;
const DERIVATION_BIP44_ETHEREUM: u8 = 1;
const PASSPHRASE_NOT_REQUIRED: u8 = 0;
const SOURCE_MNEMONIC: u8 = 1;
const SOURCE_RAW_PRIVATE_KEY: u8 = 2;
const BACKUP_CONFIRMED: u8 = 1;
const ORIGIN_GENERATED_MNEMONIC: u8 = 1;
const ORIGIN_IMPORTED_MNEMONIC: u8 = 2;
const ORIGIN_IMPORTED_RAW_KEY: u8 = 3;
const ORIGIN_MIGRATED_V1: u8 = 4;
const VAULT_AEAD_INFO: &[u8] = b"your-wallet/sepolia-demo/v2/vault-aead-v1";
const TOKEN_STORE_INFO: &[u8] = b"your-wallet/sepolia-demo/v2/token-store-v1";

// Unit tests deliberately produce a test-only wire profile that advertises
// the reduced KDF values it actually uses. Test vault bytes are not release
// artifacts and must never be persisted or treated as production-compatible.
#[cfg(test)]
const ACTIVE_ARGON2_MEMORY_KIB: u32 = 8 * 1_024;
#[cfg(not(test))]
const ACTIVE_ARGON2_MEMORY_KIB: u32 = ARGON2_MEMORY_KIB;
#[cfg(test)]
const ACTIVE_ARGON2_ITERATIONS: u32 = 1;
#[cfg(not(test))]
const ACTIVE_ARGON2_ITERATIONS: u32 = ARGON2_ITERATIONS;
#[cfg(test)]
const ACTIVE_ARGON2_PARALLELISM: u32 = 1;
#[cfg(not(test))]
const ACTIVE_ARGON2_PARALLELISM: u32 = ARGON2_PARALLELISM;

/// Stable, payload-free v2 vault errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VaultError {
    InvalidPassword,
    InvalidMetadata,
    RandomnessUnavailable,
    CryptographicFailure,
    /// Wrong passwords and every malformed, corrupt, or unauthentic vault
    /// collapse to this one category.
    AuthenticationFailed,
}

impl fmt::Display for VaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPassword => "vault password does not meet the demo policy",
            Self::InvalidMetadata => "v2 vault metadata is invalid",
            Self::RandomnessUnavailable => "operating-system randomness is unavailable",
            Self::CryptographicFailure => "v2 vault cryptographic operation failed",
            Self::AuthenticationFailed => "v2 vault could not be authenticated",
        })
    }
}

impl std::error::Error for VaultError {}

/// Raw UTF-8 password profile inherited from the demo v1 vault.
///
/// No Unicode normalization is performed, so a v1 password cannot silently
/// change bytes during migration.
pub(crate) struct VaultPassword(Zeroizing<String>);

impl VaultPassword {
    pub(crate) fn new(value: String) -> Result<Self, VaultError> {
        let value = Zeroizing::new(value);
        if !(MINIMUM_PASSWORD_BYTES..=MAXIMUM_PASSWORD_BYTES).contains(&value.len())
            || value.chars().any(char::is_control)
        {
            return Err(VaultError::InvalidPassword);
        }
        Ok(Self(value))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for VaultPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultPassword([REDACTED])")
    }
}

/// Caller-supplied provenance metadata for the wallet secret.
///
/// Sealing integrity-protects this value, but it is not independent proof of
/// how the secret was created. The backend must select it from the completed
/// generation, import, or migration flow rather than from untrusted input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VaultOrigin {
    GeneratedMnemonic,
    ImportedMnemonic,
    ImportedRawPrivateKey,
    MigratedV1RawPrivateKey,
}

impl VaultOrigin {
    const fn tag(self) -> u8 {
        match self {
            Self::GeneratedMnemonic => ORIGIN_GENERATED_MNEMONIC,
            Self::ImportedMnemonic => ORIGIN_IMPORTED_MNEMONIC,
            Self::ImportedRawPrivateKey => ORIGIN_IMPORTED_RAW_KEY,
            Self::MigratedV1RawPrivateKey => ORIGIN_MIGRATED_V1,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, VaultError> {
        match tag {
            ORIGIN_GENERATED_MNEMONIC => Ok(Self::GeneratedMnemonic),
            ORIGIN_IMPORTED_MNEMONIC => Ok(Self::ImportedMnemonic),
            ORIGIN_IMPORTED_RAW_KEY => Ok(Self::ImportedRawPrivateKey),
            ORIGIN_MIGRATED_V1 => Ok(Self::MigratedV1RawPrivateKey),
            _ => Err(VaultError::AuthenticationFailed),
        }
    }

    const fn accepts(self, source: WalletSource) -> bool {
        matches!(
            (self, source),
            (
                Self::GeneratedMnemonic | Self::ImportedMnemonic,
                WalletSource::Mnemonic
            ) | (
                Self::ImportedRawPrivateKey | Self::MigratedV1RawPrivateKey,
                WalletSource::RawPrivateKey
            )
        )
    }
}

/// Only backup-confirmed secrets may be persisted in a signable v2 vault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BackupState {
    Confirmed,
}

impl BackupState {
    const fn tag(self) -> u8 {
        match self {
            Self::Confirmed => BACKUP_CONFIRMED,
        }
    }

    fn from_tag(tag: u8) -> Result<Self, VaultError> {
        if tag == BACKUP_CONFIRMED {
            Ok(Self::Confirmed)
        } else {
            Err(VaultError::AuthenticationFailed)
        }
    }
}

/// Non-secret metadata required when sealing a new generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VaultCreationMetadata {
    origin: VaultOrigin,
    backup_state: BackupState,
    created_at_unix_seconds: u64,
    generation: u64,
}

impl VaultCreationMetadata {
    /// Marks the caller's backup-confirmation ceremony as complete.
    ///
    /// This constructor cannot attest UI provenance; the backend is
    /// responsible for passing the origin of the flow it actually completed.
    pub(crate) fn confirmed(
        origin: VaultOrigin,
        created_at_unix_seconds: u64,
        generation: u64,
    ) -> Result<Self, VaultError> {
        if created_at_unix_seconds == 0 || generation == 0 {
            return Err(VaultError::InvalidMetadata);
        }
        Ok(Self {
            origin,
            backup_state: BackupState::Confirmed,
            created_at_unix_seconds,
            generation,
        })
    }

    #[must_use]
    pub(crate) const fn origin(self) -> VaultOrigin {
        self.origin
    }

    #[must_use]
    pub(crate) const fn backup_state(self) -> BackupState {
        self.backup_state
    }

    #[must_use]
    pub(crate) const fn created_at_unix_seconds(self) -> u64 {
        self.created_at_unix_seconds
    }

    #[must_use]
    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }
}

/// Fixed-size authenticated vault bytes. The wrapper is not cloneable and has
/// redacted diagnostics even though its contents are ciphertext.
pub(crate) struct SealedVaultV2(Zeroizing<Vec<u8>>);

impl SealedVaultV2 {
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for SealedVaultV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SealedVaultV2([REDACTED])")
    }
}

/// Authenticated v2 unlock result.
pub(crate) struct OpenedVaultV2 {
    wallet: WalletSecret,
    metadata: VaultCreationMetadata,
    vault_id: [u8; VAULT_ID_BYTES],
    token_store_key: Zeroizing<[u8; 32]>,
}

impl OpenedVaultV2 {
    #[must_use]
    pub(crate) const fn wallet(&self) -> &WalletSecret {
        &self.wallet
    }

    #[must_use]
    pub(crate) const fn metadata(&self) -> VaultCreationMetadata {
        self.metadata
    }

    #[must_use]
    pub(crate) const fn vault_id(&self) -> &[u8; VAULT_ID_BYTES] {
        &self.vault_id
    }

    /// Returns only the crate-private, domain-separated demo sidecar key.
    ///
    /// The owned zeroizing value exists to feed the fixed token-store codec;
    /// callers must keep it ephemeral and must not log or persist it. No raw
    /// wallet secret or vault AEAD key is exposed.
    #[must_use]
    pub(crate) fn derive_token_store_key(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.token_store_key)
    }

    pub(crate) fn into_wallet(self) -> WalletSecret {
        self.wallet
    }
}

impl fmt::Debug for OpenedVaultV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenedVaultV2([REDACTED])")
    }
}

struct VaultHeader {
    vault_id: [u8; VAULT_ID_BYTES],
    generation: u64,
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
}

impl fmt::Debug for VaultHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultHeader([REDACTED])")
    }
}

struct VaultKeys {
    aead_key: Zeroizing<[u8; 32]>,
    token_store_key: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for VaultKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultKeys([REDACTED])")
    }
}

struct DecodedPayload {
    wallet: WalletSecret,
    origin: VaultOrigin,
    backup_state: BackupState,
    created_at_unix_seconds: u64,
}

/// Seals one confirmed v2 generation with fresh OS randomness.
pub(crate) fn seal_vault_v2(
    wallet: &WalletSecret,
    password: &VaultPassword,
    metadata: VaultCreationMetadata,
) -> Result<SealedVaultV2, VaultError> {
    if !metadata.origin.accepts(wallet.source()) || metadata.backup_state != BackupState::Confirmed
    {
        return Err(VaultError::InvalidMetadata);
    }
    let mut vault_id = [0_u8; VAULT_ID_BYTES];
    let mut salt = [0_u8; SALT_BYTES];
    let mut nonce = [0_u8; NONCE_BYTES];
    fill_random_nonzero(&mut vault_id)?;
    fill_random_nonzero(&mut salt)?;
    fill_random_nonzero(&mut nonce)?;
    let header = VaultHeader {
        vault_id,
        generation: metadata.generation,
        salt,
        nonce,
    };
    let header_bytes = encode_header(&header);
    let plaintext = encode_payload(wallet, metadata)?;
    let keys = derive_vault_keys(password, &header.salt, &header.vault_id)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(keys.aead_key.as_ref()));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&header.nonce),
            Payload {
                msg: plaintext.as_ref(),
                aad: &header_bytes,
            },
        )
        .map_err(|_| VaultError::CryptographicFailure)?;
    if ciphertext.len() != CIPHERTEXT_BYTES {
        return Err(VaultError::CryptographicFailure);
    }
    let mut output = Zeroizing::new(Vec::with_capacity(VAULT_FILE_BYTES));
    let initial_capacity = output.capacity();
    output.extend_from_slice(&header_bytes);
    output.extend_from_slice(&ciphertext);
    if output.len() != VAULT_FILE_BYTES || output.capacity() != initial_capacity {
        return Err(VaultError::CryptographicFailure);
    }
    Ok(SealedVaultV2(output))
}

/// Opens and fully revalidates one exact 256-byte v2 vault.
///
/// Wrong passwords, malformed headers, AEAD failures, invalid payload tags,
/// and account-metadata mismatches all return `AuthenticationFailed`.
pub(crate) fn open_vault_v2(
    bytes: &[u8],
    password: &VaultPassword,
) -> Result<OpenedVaultV2, VaultError> {
    open_vault_v2_inner(bytes, password).map_err(|_| VaultError::AuthenticationFailed)
}

fn open_vault_v2_inner(
    bytes: &[u8],
    password: &VaultPassword,
) -> Result<OpenedVaultV2, VaultError> {
    let header = parse_header(bytes)?;
    let keys = derive_vault_keys(password, &header.salt, &header.vault_id)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(keys.aead_key.as_ref()));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&header.nonce),
            Payload {
                msg: bytes
                    .get(VAULT_HEADER_BYTES..)
                    .ok_or(VaultError::AuthenticationFailed)?,
                aad: bytes
                    .get(..VAULT_HEADER_BYTES)
                    .ok_or(VaultError::AuthenticationFailed)?,
            },
        )
        .map_err(|_| VaultError::AuthenticationFailed)?;
    let plaintext = Zeroizing::new(plaintext);
    let decoded = decode_payload(plaintext.as_slice())?;
    let metadata = VaultCreationMetadata {
        origin: decoded.origin,
        backup_state: decoded.backup_state,
        created_at_unix_seconds: decoded.created_at_unix_seconds,
        generation: header.generation,
    };
    Ok(OpenedVaultV2 {
        wallet: decoded.wallet,
        metadata,
        vault_id: header.vault_id,
        token_store_key: keys.token_store_key,
    })
}

fn encode_header(header: &VaultHeader) -> [u8; VAULT_HEADER_BYTES] {
    let mut bytes = [0_u8; VAULT_HEADER_BYTES];
    bytes[0..8].copy_from_slice(VAULT_MAGIC);
    put_u16(&mut bytes, 8, VAULT_VERSION);
    put_u16(&mut bytes, 10, VAULT_HEADER_BYTES_U16);
    put_u16(&mut bytes, 12, PASSWORD_PROFILE);
    put_u16(&mut bytes, 14, KDF_ARGON2ID);
    put_u16(&mut bytes, 16, AEAD_XCHACHA20_POLY1305);
    put_u16(&mut bytes, 18, PAYLOAD_SCHEMA);
    put_u32(&mut bytes, 20, ACTIVE_ARGON2_MEMORY_KIB);
    put_u32(&mut bytes, 24, ACTIVE_ARGON2_ITERATIONS);
    put_u32(&mut bytes, 28, ACTIVE_ARGON2_PARALLELISM);
    bytes[32..48].copy_from_slice(&header.vault_id);
    put_u64(&mut bytes, 48, header.generation);
    bytes[56..72].copy_from_slice(&header.salt);
    bytes[72..96].copy_from_slice(&header.nonce);
    put_u32(&mut bytes, 96, CIPHERTEXT_BYTES as u32);
    put_u32(&mut bytes, 100, SEPOLIA_CHAIN_ID);
    put_u32(&mut bytes, 104, 0);
    put_u32(&mut bytes, 108, 0);
    bytes
}

fn parse_header(bytes: &[u8]) -> Result<VaultHeader, VaultError> {
    if bytes.len() != VAULT_FILE_BYTES
        || bytes.get(0..8) != Some(VAULT_MAGIC.as_slice())
        || read_u16(bytes, 8)? != VAULT_VERSION
        || read_u16(bytes, 10)? != VAULT_HEADER_BYTES_U16
        || read_u16(bytes, 12)? != PASSWORD_PROFILE
        || read_u16(bytes, 14)? != KDF_ARGON2ID
        || read_u16(bytes, 16)? != AEAD_XCHACHA20_POLY1305
        || read_u16(bytes, 18)? != PAYLOAD_SCHEMA
        || read_u32(bytes, 20)? != ACTIVE_ARGON2_MEMORY_KIB
        || read_u32(bytes, 24)? != ACTIVE_ARGON2_ITERATIONS
        || read_u32(bytes, 28)? != ACTIVE_ARGON2_PARALLELISM
        || read_u32(bytes, 96)? != CIPHERTEXT_BYTES as u32
        || read_u32(bytes, 100)? != SEPOLIA_CHAIN_ID
        || read_u32(bytes, 104)? != 0
        || read_u32(bytes, 108)? != 0
    {
        return Err(VaultError::AuthenticationFailed);
    }
    let vault_id = array_at::<VAULT_ID_BYTES>(bytes, 32)?;
    let generation = read_u64(bytes, 48)?;
    let salt = array_at::<SALT_BYTES>(bytes, 56)?;
    let nonce = array_at::<NONCE_BYTES>(bytes, 72)?;
    if vault_id == [0; VAULT_ID_BYTES]
        || generation == 0
        || salt == [0; SALT_BYTES]
        || nonce == [0; NONCE_BYTES]
    {
        return Err(VaultError::AuthenticationFailed);
    }
    Ok(VaultHeader {
        vault_id,
        generation,
        salt,
        nonce,
    })
}

fn encode_payload(
    wallet: &WalletSecret,
    metadata: VaultCreationMetadata,
) -> Result<Zeroizing<[u8; PAYLOAD_BYTES]>, VaultError> {
    if !metadata.origin.accepts(wallet.source()) || metadata.created_at_unix_seconds == 0 {
        return Err(VaultError::InvalidMetadata);
    }
    let material = wallet.encoded_secret_material();
    let mut bytes = Zeroizing::new([0_u8; PAYLOAD_BYTES]);
    bytes[0..8].copy_from_slice(PAYLOAD_MAGIC);
    put_u16(bytes.as_mut(), 8, PAYLOAD_SCHEMA);
    bytes[10] = match material.source() {
        WalletSource::Mnemonic => SOURCE_MNEMONIC,
        WalletSource::RawPrivateKey => SOURCE_RAW_PRIVATE_KEY,
    };
    bytes[11] = metadata.origin.tag();
    bytes[12] = metadata.backup_state.tag();
    bytes[13] = match wallet.source() {
        WalletSource::Mnemonic => LANGUAGE_ENGLISH,
        WalletSource::RawPrivateKey => LANGUAGE_RAW_SENTINEL,
    };
    bytes[14] = wallet.word_count().unwrap_or(0);
    bytes[15] = match wallet.source() {
        WalletSource::Mnemonic => DERIVATION_BIP44_ETHEREUM,
        WalletSource::RawPrivateKey => DERIVATION_RAW_SENTINEL,
    };
    bytes[16] = PASSPHRASE_NOT_REQUIRED;
    bytes[17] = wallet.account_count();
    put_u64(bytes.as_mut(), 24, metadata.created_at_unix_seconds);
    let account_zero = wallet.account(0).ok_or(VaultError::InvalidMetadata)?;
    encode_account(bytes.as_mut(), 32, account_zero);
    if let Some(account_one) = wallet.account(1) {
        encode_account(bytes.as_mut(), 60, account_one);
    }
    put_u16(bytes.as_mut(), 88, u16::from(material.length()));
    bytes[96..128].copy_from_slice(material.as_padded_bytes());
    Ok(bytes)
}

fn decode_payload(bytes: &[u8]) -> Result<DecodedPayload, VaultError> {
    if bytes.len() != PAYLOAD_BYTES
        || bytes.get(0..8) != Some(PAYLOAD_MAGIC.as_slice())
        || read_u16(bytes, 8)? != PAYLOAD_SCHEMA
        || bytes.get(18..24).is_none_or(|reserved| reserved != [0; 6])
        || bytes.get(90..96).is_none_or(|reserved| reserved != [0; 6])
    {
        return Err(VaultError::AuthenticationFailed);
    }
    let source = match bytes[10] {
        SOURCE_MNEMONIC => WalletSource::Mnemonic,
        SOURCE_RAW_PRIVATE_KEY => WalletSource::RawPrivateKey,
        _ => return Err(VaultError::AuthenticationFailed),
    };
    let origin = VaultOrigin::from_tag(bytes[11])?;
    let backup_state = BackupState::from_tag(bytes[12])?;
    if !origin.accepts(source) || bytes[16] != PASSPHRASE_NOT_REQUIRED || bytes[17] == 0 {
        return Err(VaultError::AuthenticationFailed);
    }
    let created_at_unix_seconds = read_u64(bytes, 24)?;
    if created_at_unix_seconds == 0 {
        return Err(VaultError::AuthenticationFailed);
    }
    let encoded_accounts = [decode_account(bytes, 32)?, decode_account(bytes, 60)?];
    let secret_length = usize::from(read_u16(bytes, 88)?);
    if secret_length > 32
        || bytes
            .get(96 + secret_length..128)
            .is_none_or(|padding| padding.iter().any(|byte| *byte != 0))
    {
        return Err(VaultError::AuthenticationFailed);
    }
    let mut secret_bytes = Zeroizing::new([0_u8; 32]);
    secret_bytes.copy_from_slice(bytes.get(96..128).ok_or(VaultError::AuthenticationFailed)?);
    let wallet = match source {
        WalletSource::Mnemonic => {
            if bytes[13] != LANGUAGE_ENGLISH
                || bytes[15] != DERIVATION_BIP44_ETHEREUM
                || bytes[17] != 2
                || !matches!(secret_length, 16 | 20 | 24 | 28 | 32)
                || bytes[14] != ((secret_length as u8 / 4) * 3)
            {
                return Err(VaultError::AuthenticationFailed);
            }
            WalletSecret::from_mnemonic_entropy(secret_bytes, secret_length)
                .map_err(collapse_secret_error)?
        }
        WalletSource::RawPrivateKey => {
            if bytes[13] != LANGUAGE_RAW_SENTINEL
                || bytes[14] != 0
                || bytes[15] != DERIVATION_RAW_SENTINEL
                || bytes[17] != 1
                || secret_length != 32
                || encoded_accounts[1] != empty_account_metadata()
            {
                return Err(VaultError::AuthenticationFailed);
            }
            WalletSecret::from_raw_private_key_bytes(secret_bytes).map_err(collapse_secret_error)?
        }
    };
    if wallet.source() != source
        || wallet.account_count() != bytes[17]
        || wallet.account(0) != Some(encoded_accounts[0])
        || wallet.account(1).unwrap_or_else(empty_account_metadata) != encoded_accounts[1]
    {
        return Err(VaultError::AuthenticationFailed);
    }
    Ok(DecodedPayload {
        wallet,
        origin,
        backup_state,
        created_at_unix_seconds,
    })
}

fn encode_account(bytes: &mut [u8], offset: usize, account: AccountMetadata) {
    put_u32(bytes, offset, account.requested_index());
    put_u32(bytes, offset + 4, account.actual_index());
    bytes[offset + 8..offset + 28].copy_from_slice(account.address().as_bytes());
}

fn decode_account(bytes: &[u8], offset: usize) -> Result<AccountMetadata, VaultError> {
    Ok(AccountMetadata::new(
        read_u32(bytes, offset)?,
        read_u32(bytes, offset + 4)?,
        EthereumAddress::from_bytes(array_at::<20>(bytes, offset + 8)?),
    ))
}

const fn empty_account_metadata() -> AccountMetadata {
    AccountMetadata::new(0, 0, EthereumAddress::from_bytes([0; 20]))
}

fn derive_vault_keys(
    password: &VaultPassword,
    salt: &[u8; SALT_BYTES],
    vault_id: &[u8; VAULT_ID_BYTES],
) -> Result<VaultKeys, VaultError> {
    let parameters = Params::new(
        ACTIVE_ARGON2_MEMORY_KIB,
        ACTIVE_ARGON2_ITERATIONS,
        ACTIVE_ARGON2_PARALLELISM,
        Some(32),
    )
    .map_err(|_| VaultError::CryptographicFailure)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters);
    let mut master = Zeroizing::new([0_u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, master.as_mut())
        .map_err(|_| VaultError::CryptographicFailure)?;
    let hkdf = Hkdf::<Sha256>::new(Some(vault_id), master.as_ref());
    let mut aead_key = Zeroizing::new([0_u8; 32]);
    let mut token_store_key = Zeroizing::new([0_u8; 32]);
    hkdf.expand(VAULT_AEAD_INFO, aead_key.as_mut())
        .map_err(|_| VaultError::CryptographicFailure)?;
    hkdf.expand(TOKEN_STORE_INFO, token_store_key.as_mut())
        .map_err(|_| VaultError::CryptographicFailure)?;
    if aead_key.as_ref() == token_store_key.as_ref() {
        return Err(VaultError::CryptographicFailure);
    }
    Ok(VaultKeys {
        aead_key,
        token_store_key,
    })
}

fn fill_random_nonzero<const N: usize>(output: &mut [u8; N]) -> Result<(), VaultError> {
    for _ in 0..8 {
        getrandom::fill(output).map_err(|_| VaultError::RandomnessUnavailable)?;
        if *output != [0; N] {
            return Ok(());
        }
    }
    output.zeroize();
    Err(VaultError::RandomnessUnavailable)
}

const fn collapse_secret_error(_: SecretError) -> VaultError {
    VaultError::AuthenticationFailed
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

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, VaultError> {
    Ok(u16::from_be_bytes(array_at(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, VaultError> {
    Ok(u32::from_be_bytes(array_at(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, VaultError> {
    Ok(u64::from_be_bytes(array_at(bytes, offset)?))
}

fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], VaultError> {
    bytes
        .get(offset..offset.saturating_add(N))
        .and_then(|slice| slice.try_into().ok())
        .ok_or(VaultError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use argon2::Params;
    use zeroize::Zeroizing;

    use super::{
        ACTIVE_ARGON2_ITERATIONS, ACTIVE_ARGON2_MEMORY_KIB, ACTIVE_ARGON2_PARALLELISM,
        ARGON2_ITERATIONS, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, BackupState, CIPHERTEXT_BYTES,
        PAYLOAD_BYTES, SEPOLIA_CHAIN_ID, VAULT_FILE_BYTES, VAULT_HEADER_BYTES,
        VaultCreationMetadata, VaultError, VaultOrigin, VaultPassword, decode_payload,
        derive_vault_keys, encode_payload, open_vault_v2, parse_header, seal_vault_v2,
    };
    use crate::wallet_secret::{SecretInput, WalletSecret};

    const TEST_PASSWORD: &str = "public-test-password";
    const ZERO_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn fixed_layout_and_test_only_kdf_profile_are_exact() {
        assert_eq!(VAULT_HEADER_BYTES, 112);
        assert_eq!(PAYLOAD_BYTES, 128);
        assert_eq!(CIPHERTEXT_BYTES, 144);
        assert_eq!(VAULT_FILE_BYTES, 256);
        // Test wire bytes advertise these reduced values and are intentionally
        // incompatible with release vaults. The release profile remains fixed
        // and independently checked for constructibility below.
        assert_eq!(ACTIVE_ARGON2_MEMORY_KIB, 8 * 1_024);
        assert_eq!(ACTIVE_ARGON2_ITERATIONS, 1);
        assert_eq!(ACTIVE_ARGON2_PARALLELISM, 1);
        assert!(
            Params::new(
                ARGON2_MEMORY_KIB,
                ARGON2_ITERATIONS,
                ARGON2_PARALLELISM,
                Some(32)
            )
            .is_ok()
        );
        assert_eq!(SEPOLIA_CHAIN_ID, 11_155_111);
    }

    #[test]
    fn mnemonic_round_trip_recomputes_accounts_and_stable_token_capability()
    -> Result<(), VaultError> {
        let wallet = WalletSecret::import_mnemonic(SecretInput::new(ZERO_MNEMONIC.to_owned()))
            .map_err(|_| VaultError::InvalidMetadata)?;
        let expected_accounts = [wallet.account(0), wallet.account(1)];
        let password = VaultPassword::new(TEST_PASSWORD.to_owned())?;
        let metadata =
            VaultCreationMetadata::confirmed(VaultOrigin::GeneratedMnemonic, 1_700_000_000, 7)?;
        let sealed = seal_vault_v2(&wallet, &password, metadata)?;
        assert_eq!(sealed.as_bytes().len(), VAULT_FILE_BYTES);
        let opened = open_vault_v2(sealed.as_bytes(), &password)?;
        assert_eq!(opened.metadata(), metadata);
        assert_eq!(opened.wallet().account(0), expected_accounts[0]);
        assert_eq!(opened.wallet().account(1), expected_accounts[1]);
        let first_key = opened.derive_token_store_key();
        let second_key = opened.derive_token_store_key();
        assert_eq!(first_key.as_ref(), second_key.as_ref());
        assert_ne!(first_key.as_ref(), &[0_u8; 32]);
        assert_ne!(opened.vault_id(), &[0_u8; 16]);
        Ok(())
    }

    #[test]
    fn raw_key_round_trip_enforces_origin_and_one_account() -> Result<(), VaultError> {
        let wallet = WalletSecret::import_raw_private_key(SecretInput::new("07".repeat(32)))
            .map_err(|_| VaultError::InvalidMetadata)?;
        let password = VaultPassword::new(TEST_PASSWORD.to_owned())?;
        let metadata = VaultCreationMetadata::confirmed(
            VaultOrigin::MigratedV1RawPrivateKey,
            1_700_000_001,
            1,
        )?;
        let sealed = seal_vault_v2(&wallet, &password, metadata)?;
        let opened = open_vault_v2(sealed.as_bytes(), &password)?;
        assert_eq!(opened.wallet().account_count(), 1);
        assert!(opened.wallet().account(1).is_none());
        assert_eq!(
            opened.metadata().origin(),
            VaultOrigin::MigratedV1RawPrivateKey
        );
        assert_eq!(opened.metadata().backup_state(), BackupState::Confirmed);
        assert_eq!(opened.metadata().created_at_unix_seconds(), 1_700_000_001);
        assert_eq!(opened.metadata().generation(), 1);
        Ok(())
    }

    #[test]
    fn source_origin_mismatches_fail_before_sealing() -> Result<(), VaultError> {
        let mnemonic = WalletSecret::import_mnemonic(SecretInput::new(ZERO_MNEMONIC.to_owned()))
            .map_err(|_| VaultError::InvalidMetadata)?;
        let raw = WalletSecret::import_raw_private_key(SecretInput::new("07".repeat(32)))
            .map_err(|_| VaultError::InvalidMetadata)?;
        let password = VaultPassword::new(TEST_PASSWORD.to_owned())?;
        let raw_origin =
            VaultCreationMetadata::confirmed(VaultOrigin::ImportedRawPrivateKey, 1_700_000_000, 1)?;
        let mnemonic_origin =
            VaultCreationMetadata::confirmed(VaultOrigin::ImportedMnemonic, 1_700_000_000, 1)?;
        assert!(matches!(
            seal_vault_v2(&mnemonic, &password, raw_origin),
            Err(VaultError::InvalidMetadata)
        ));
        assert!(matches!(
            seal_vault_v2(&raw, &password, mnemonic_origin),
            Err(VaultError::InvalidMetadata)
        ));
        Ok(())
    }

    #[test]
    fn wrong_password_ciphertext_corruption_and_lengths_collapse() -> Result<(), VaultError> {
        let wallet = WalletSecret::import_mnemonic(SecretInput::new(ZERO_MNEMONIC.to_owned()))
            .map_err(|_| VaultError::InvalidMetadata)?;
        let password = VaultPassword::new(TEST_PASSWORD.to_owned())?;
        let wrong = VaultPassword::new("different-test-password".to_owned())?;
        let metadata =
            VaultCreationMetadata::confirmed(VaultOrigin::ImportedMnemonic, 1_700_000_000, 1)?;
        let sealed = seal_vault_v2(&wallet, &password, metadata)?;
        assert!(matches!(
            open_vault_v2(sealed.as_bytes(), &wrong),
            Err(VaultError::AuthenticationFailed)
        ));

        let mut corrupt = sealed.as_bytes().to_vec();
        corrupt[VAULT_FILE_BYTES - 1] ^= 1;
        assert!(matches!(
            open_vault_v2(&corrupt, &password),
            Err(VaultError::AuthenticationFailed)
        ));
        for length in [0, VAULT_HEADER_BYTES, VAULT_FILE_BYTES - 1] {
            assert!(matches!(
                open_vault_v2(&sealed.as_bytes()[..length], &password),
                Err(VaultError::AuthenticationFailed)
            ));
        }
        let mut trailing = sealed.as_bytes().to_vec();
        trailing.push(0);
        assert!(matches!(
            open_vault_v2(&trailing, &password),
            Err(VaultError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn header_unknown_flags_reserved_chain_and_zero_values_are_rejected() -> Result<(), VaultError>
    {
        let wallet = WalletSecret::import_raw_private_key(SecretInput::new("07".repeat(32)))
            .map_err(|_| VaultError::InvalidMetadata)?;
        let password = VaultPassword::new(TEST_PASSWORD.to_owned())?;
        let metadata =
            VaultCreationMetadata::confirmed(VaultOrigin::ImportedRawPrivateKey, 1_700_000_000, 1)?;
        let sealed = seal_vault_v2(&wallet, &password, metadata)?;
        for offset in [
            0_usize, 8, 10, 12, 14, 16, 18, 20, 24, 28, 32, 56, 72, 96, 100, 104, 108,
        ] {
            let mut bytes = sealed.as_bytes().to_vec();
            if matches!(offset, 32 | 56 | 72) {
                let length = match offset {
                    72 => 24,
                    _ => 16,
                };
                bytes[offset..offset + length].fill(0);
            } else {
                bytes[offset] ^= 1;
            }
            assert!(matches!(
                parse_header(&bytes),
                Err(VaultError::AuthenticationFailed)
            ));
        }
        let mut generation_tamper = sealed.as_bytes().to_vec();
        generation_tamper[48] ^= 1;
        assert!(parse_header(&generation_tamper).is_ok());
        assert!(matches!(
            open_vault_v2(&generation_tamper, &password),
            Err(VaultError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn payload_rejects_unknown_tags_reserved_bytes_padding_and_account_mismatch()
    -> Result<(), VaultError> {
        let wallet = WalletSecret::import_mnemonic(SecretInput::new(ZERO_MNEMONIC.to_owned()))
            .map_err(|_| VaultError::InvalidMetadata)?;
        let metadata =
            VaultCreationMetadata::confirmed(VaultOrigin::GeneratedMnemonic, 1_700_000_000, 1)?;
        let payload = encode_payload(&wallet, metadata)?;
        for offset in [
            0_usize, 8, 10, 11, 12, 13, 14, 15, 16, 17, 18, 32, 40, 60, 88, 90, 112,
        ] {
            let mut corrupt = payload.to_vec();
            corrupt[offset] ^= 0xff;
            assert!(matches!(
                decode_payload(&corrupt),
                Err(VaultError::AuthenticationFailed)
            ));
        }
        let mut trailing = payload.to_vec();
        trailing.push(0);
        assert!(matches!(
            decode_payload(&trailing),
            Err(VaultError::AuthenticationFailed)
        ));
        Ok(())
    }

    #[test]
    fn token_store_key_is_domain_separated_and_bound_to_vault_id() -> Result<(), VaultError> {
        let password = VaultPassword::new(TEST_PASSWORD.to_owned())?;
        let salt = [0x22; 16];
        let first_id = [0x33; 16];
        let second_id = [0x44; 16];
        let first = derive_vault_keys(&password, &salt, &first_id)?;
        let second = derive_vault_keys(&password, &salt, &second_id)?;
        assert_ne!(first.aead_key.as_ref(), first.token_store_key.as_ref());
        assert_ne!(
            first.token_store_key.as_ref(),
            second.token_store_key.as_ref()
        );
        Ok(())
    }

    #[test]
    fn password_and_debug_surfaces_are_bounded_and_redacted() -> Result<(), VaultError> {
        for invalid in [
            "short".to_owned(),
            "valid-length\n".to_owned(),
            "x".repeat(1_025),
        ] {
            assert!(matches!(
                VaultPassword::new(invalid),
                Err(VaultError::InvalidPassword)
            ));
        }
        let marker = TEST_PASSWORD.to_owned();
        let password = VaultPassword::new(marker.clone())?;
        assert!(!format!("{password:?}").contains(&marker));
        let wallet = WalletSecret::import_raw_private_key(SecretInput::new("07".repeat(32)))
            .map_err(|_| VaultError::InvalidMetadata)?;
        let metadata =
            VaultCreationMetadata::confirmed(VaultOrigin::ImportedRawPrivateKey, 1_700_000_000, 1)?;
        let sealed = seal_vault_v2(&wallet, &password, metadata)?;
        let opened = open_vault_v2(sealed.as_bytes(), &password)?;
        for rendered in [
            format!("{sealed:?}"),
            format!("{opened:?}"),
            format!("{:?}", opened.wallet()),
        ] {
            assert!(rendered.contains("[REDACTED]"));
            assert!(!rendered.contains(&marker));
            assert!(!rendered.contains(&"07".repeat(32)));
        }
        let _wallet = opened.into_wallet();
        Ok(())
    }

    #[test]
    fn random_header_values_are_nonzero_and_fresh() -> Result<(), VaultError> {
        let wallet = WalletSecret::import_raw_private_key(SecretInput::new("07".repeat(32)))
            .map_err(|_| VaultError::InvalidMetadata)?;
        let password = VaultPassword::new(TEST_PASSWORD.to_owned())?;
        let metadata =
            VaultCreationMetadata::confirmed(VaultOrigin::ImportedRawPrivateKey, 1_700_000_000, 1)?;
        let first = seal_vault_v2(&wallet, &password, metadata)?;
        let second = seal_vault_v2(&wallet, &password, metadata)?;
        let first_header = parse_header(first.as_bytes())?;
        let second_header = parse_header(second.as_bytes())?;
        assert_ne!(first_header.vault_id, second_header.vault_id);
        assert_ne!(first_header.salt, second_header.salt);
        assert_ne!(first_header.nonce, second_header.nonce);
        Ok(())
    }

    #[test]
    fn payload_decoder_accepts_all_supported_mnemonic_entropy_lengths() -> Result<(), VaultError> {
        for length in [16_usize, 20, 24, 28, 32] {
            let entropy = Zeroizing::new([0_u8; 32]);
            let wallet = WalletSecret::from_mnemonic_entropy(entropy, length)
                .map_err(|_| VaultError::InvalidMetadata)?;
            let metadata =
                VaultCreationMetadata::confirmed(VaultOrigin::ImportedMnemonic, 1_700_000_000, 1)?;
            let payload = encode_payload(&wallet, metadata)?;
            let decoded = decode_payload(payload.as_ref())?;
            assert_eq!(decoded.wallet.word_count(), wallet.word_count());
            assert_eq!(decoded.wallet.account(0), wallet.account(0));
            assert_eq!(decoded.wallet.account(1), wallet.account(1));
        }
        Ok(())
    }
}
