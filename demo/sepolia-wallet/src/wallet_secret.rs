//! Demo-local secret generation, import, and deterministic Ethereum derivation.
//!
//! This module intentionally does not depend on the production `secret-core`
//! crate. It supports only English BIP-39, the empty BIP-39 passphrase, and the
//! two exact demo paths `m/44'/60'/0'/0/0` and `m/44'/60'/0'/0/1`.

#![cfg_attr(not(test), allow(dead_code))]

use core::fmt;

use bip39::{Language, Mnemonic};
use hmac::{Hmac, Mac as _};
use pbkdf2::pbkdf2_hmac;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};
use sha2::Sha512;
use sha3::{Digest as _, Keccak256};
use zeroize::{Zeroize as _, Zeroizing};

const BIP39_PBKDF2_ROUNDS: u32 = 2_048;
const BIP39_EMPTY_PASSPHRASE_SALT: &[u8] = b"mnemonic";
const BIP32_ROOT_KEY: &[u8] = b"Bitcoin seed";
const HARDENED_OFFSET: u32 = 1 << 31;
const DEFAULT_PATH_PREFIX: [u32; 4] = [
    44 | HARDENED_OFFSET,
    60 | HARDENED_OFFSET,
    HARDENED_OFFSET,
    0,
];
const MANAGED_ACCOUNT_COUNT: usize = 2;
const MAX_MNEMONIC_INPUT_BYTES: usize = 4_096;
const PRIVATE_KEY_BYTES: usize = 32;
const MAX_ENTROPY_BYTES: usize = 32;

type HmacSha512 = Hmac<Sha512>;

/// Stable, payload-free secret handling errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecretError {
    RandomnessUnavailable,
    InvalidMnemonic,
    InvalidPrivateKey,
    UnsupportedAccount,
    ExportUnavailable,
    DerivationFailed,
    CryptographicFailure,
}

impl fmt::Display for SecretError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RandomnessUnavailable => "operating-system randomness is unavailable",
            Self::InvalidMnemonic => "English BIP-39 mnemonic is invalid",
            Self::InvalidPrivateKey => "secp256k1 private key is invalid",
            Self::UnsupportedAccount => "demo account index is unsupported",
            Self::ExportUnavailable => "requested secret export is unavailable",
            Self::DerivationFailed => "BIP-32 account derivation failed",
            Self::CryptographicFailure => "secret cryptographic operation failed",
        })
    }
}

impl std::error::Error for SecretError {}

/// Supported sizes for newly generated English mnemonics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MnemonicWordCount {
    Twelve,
    TwentyFour,
}

impl MnemonicWordCount {
    const fn entropy_bytes(self) -> usize {
        match self {
            Self::Twelve => 16,
            Self::TwentyFour => 32,
        }
    }
}

/// The persisted source category. It contains no secret payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WalletSource {
    Mnemonic,
    RawPrivateKey,
}

/// Exact Ethereum address. Debug output is deliberately redacted because an
/// account address is identifying metadata.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub(crate) struct EthereumAddress([u8; 20]);

impl EthereumAddress {
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub(crate) const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl fmt::Debug for EthereumAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EthereumAddress([REDACTED])")
    }
}

/// Public metadata for one exact managed path.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct AccountMetadata {
    requested_index: u32,
    actual_index: u32,
    address: EthereumAddress,
}

impl AccountMetadata {
    #[must_use]
    pub(crate) const fn new(
        requested_index: u32,
        actual_index: u32,
        address: EthereumAddress,
    ) -> Self {
        Self {
            requested_index,
            actual_index,
            address,
        }
    }

    #[must_use]
    pub(crate) const fn requested_index(self) -> u32 {
        self.requested_index
    }

    #[must_use]
    pub(crate) const fn actual_index(self) -> u32 {
        self.actual_index
    }

    #[must_use]
    pub(crate) const fn address(self) -> EthereumAddress {
        self.address
    }
}

impl fmt::Debug for AccountMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccountMetadata")
            .field("requested_index", &self.requested_index)
            .field("actual_index", &self.actual_index)
            .field("address", &"[REDACTED]")
            .finish()
    }
}

/// Owned one-shot secret input. It is not cloneable and zeroizes its backing
/// allocation on drop.
pub(crate) struct SecretInput(Zeroizing<String>);

impl SecretInput {
    #[must_use]
    pub(crate) fn new(value: String) -> Self {
        Self(Zeroizing::new(value))
    }

    fn expose_secret(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretInput([REDACTED])")
    }
}

/// Category of a one-shot secret export.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SecretExportKind {
    Mnemonic,
    AccountPrivateKey,
}

/// One-shot text export. The value is not cloneable and is zeroized on drop.
pub(crate) struct SecretExport {
    kind: SecretExportKind,
    text: Zeroizing<String>,
}

impl SecretExport {
    #[must_use]
    pub(crate) const fn kind(&self) -> SecretExportKind {
        self.kind
    }

    /// Exposes the value only to the trusted one-shot reveal path.
    #[must_use]
    pub(crate) fn expose_secret(&self) -> &str {
        self.text.as_str()
    }

    /// Transfers the one-shot reveal without copying its secret allocation.
    #[must_use]
    pub(crate) fn into_zeroizing_text(self) -> (SecretExportKind, Zeroizing<String>) {
        (self.kind, self.text)
    }
}

impl fmt::Debug for SecretExport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretExport([REDACTED])")
    }
}

/// One derived private key with zeroizing ownership and redacted diagnostics.
pub(crate) struct AccountPrivateKey(Zeroizing<[u8; PRIVATE_KEY_BYTES]>);

impl AccountPrivateKey {
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8; PRIVATE_KEY_BYTES] {
        &self.0
    }
}

impl fmt::Debug for AccountPrivateKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AccountPrivateKey([REDACTED])")
    }
}

/// Fixed-size secret material used only by the authenticated v2 codec.
pub(crate) struct EncodedSecretMaterial {
    source: WalletSource,
    bytes: Zeroizing<[u8; MAX_ENTROPY_BYTES]>,
    length: u8,
}

impl EncodedSecretMaterial {
    #[must_use]
    pub(crate) const fn source(&self) -> WalletSource {
        self.source
    }

    #[must_use]
    pub(crate) const fn length(&self) -> u8 {
        self.length
    }

    #[must_use]
    pub(crate) fn as_padded_bytes(&self) -> &[u8; MAX_ENTROPY_BYTES] {
        &self.bytes
    }
}

impl fmt::Debug for EncodedSecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EncodedSecretMaterial([REDACTED])")
    }
}

/// Validated demo wallet secret and recomputed account metadata.
///
/// This type intentionally implements neither `Clone` nor serialization.
pub(crate) enum WalletSecret {
    Mnemonic {
        entropy: Zeroizing<[u8; MAX_ENTROPY_BYTES]>,
        entropy_length: u8,
        accounts: [AccountMetadata; MANAGED_ACCOUNT_COUNT],
    },
    RawPrivateKey {
        private_key: Zeroizing<[u8; PRIVATE_KEY_BYTES]>,
        account: AccountMetadata,
    },
}

impl fmt::Debug for WalletSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Mnemonic { .. } => "WalletSecret::Mnemonic([REDACTED])",
            Self::RawPrivateKey { .. } => "WalletSecret::RawPrivateKey([REDACTED])",
        })
    }
}

impl WalletSecret {
    /// Generates a new 12- or 24-word English mnemonic from the OS CSPRNG.
    pub(crate) fn generate_mnemonic(words: MnemonicWordCount) -> Result<Self, SecretError> {
        let entropy_length = words.entropy_bytes();
        let mut entropy = Zeroizing::new([0_u8; MAX_ENTROPY_BYTES]);
        getrandom::fill(&mut entropy[..entropy_length])
            .map_err(|_| SecretError::RandomnessUnavailable)?;
        Self::from_mnemonic_entropy(entropy, entropy_length)
    }

    /// Imports an English 12/15/18/21/24-word phrase and validates checksum.
    pub(crate) fn import_mnemonic(input: SecretInput) -> Result<Self, SecretError> {
        let phrase = input.expose_secret();
        validate_mnemonic_shape(phrase)?;
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|_| SecretError::InvalidMnemonic)?;
        validate_import_word_count(mnemonic.word_count())?;
        let (padded, entropy_length) = entropy_from_mnemonic(&mnemonic)?;
        Self::from_mnemonic_entropy(padded, entropy_length)
    }

    /// Strictly imports 64 hexadecimal digits, optionally prefixed by `0x`.
    pub(crate) fn import_raw_private_key(input: SecretInput) -> Result<Self, SecretError> {
        let value = input.expose_secret();
        let digits = value.strip_prefix("0x").unwrap_or(value);
        if digits.len() != PRIVATE_KEY_BYTES * 2
            || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(SecretError::InvalidPrivateKey);
        }
        let mut private_key = Zeroizing::new([0_u8; PRIVATE_KEY_BYTES]);
        for (index, output) in private_key.iter_mut().enumerate() {
            let high =
                hex_nibble(digits.as_bytes()[index * 2]).ok_or(SecretError::InvalidPrivateKey)?;
            let low = hex_nibble(digits.as_bytes()[index * 2 + 1])
                .ok_or(SecretError::InvalidPrivateKey)?;
            *output = (high << 4) | low;
        }
        Self::from_raw_private_key_bytes(private_key)
    }

    /// Reconstructs a mnemonic wallet from fixed-size decrypted entropy.
    pub(crate) fn from_mnemonic_entropy(
        entropy: Zeroizing<[u8; MAX_ENTROPY_BYTES]>,
        entropy_length: usize,
    ) -> Result<Self, SecretError> {
        validate_entropy_length(entropy_length)?;
        if entropy[entropy_length..].iter().any(|byte| *byte != 0) {
            return Err(SecretError::InvalidMnemonic);
        }
        Mnemonic::from_entropy_in(Language::English, &entropy[..entropy_length])
            .map_err(|_| SecretError::InvalidMnemonic)?;
        let accounts = [
            derive_exact_account(&entropy[..entropy_length], 0)?.metadata,
            derive_exact_account(&entropy[..entropy_length], 1)?.metadata,
        ];
        Ok(Self::Mnemonic {
            entropy,
            entropy_length: u8::try_from(entropy_length)
                .map_err(|_| SecretError::InvalidMnemonic)?,
            accounts,
        })
    }

    /// Reconstructs a raw-key wallet from decrypted key bytes.
    pub(crate) fn from_raw_private_key_bytes(
        private_key: Zeroizing<[u8; PRIVATE_KEY_BYTES]>,
    ) -> Result<Self, SecretError> {
        let address = address_from_private_key(&private_key)?;
        Ok(Self::RawPrivateKey {
            private_key,
            account: AccountMetadata {
                requested_index: 0,
                actual_index: 0,
                address,
            },
        })
    }

    #[must_use]
    pub(crate) const fn source(&self) -> WalletSource {
        match self {
            Self::Mnemonic { .. } => WalletSource::Mnemonic,
            Self::RawPrivateKey { .. } => WalletSource::RawPrivateKey,
        }
    }

    #[must_use]
    pub(crate) const fn word_count(&self) -> Option<u8> {
        match self {
            Self::Mnemonic { entropy_length, .. } => Some((*entropy_length / 4) * 3),
            Self::RawPrivateKey { .. } => None,
        }
    }

    #[must_use]
    pub(crate) const fn account_count(&self) -> u8 {
        match self {
            Self::Mnemonic { .. } => MANAGED_ACCOUNT_COUNT as u8,
            Self::RawPrivateKey { .. } => 1,
        }
    }

    #[must_use]
    pub(crate) fn account(&self, position: usize) -> Option<AccountMetadata> {
        match self {
            Self::Mnemonic { accounts, .. } => accounts.get(position).copied(),
            Self::RawPrivateKey { account, .. } if position == 0 => Some(*account),
            Self::RawPrivateKey { .. } => None,
        }
    }

    /// Derives or copies one exact account key into zeroizing ownership.
    pub(crate) fn account_private_key(
        &self,
        account_index: u32,
    ) -> Result<AccountPrivateKey, SecretError> {
        match self {
            Self::Mnemonic {
                entropy,
                entropy_length,
                accounts,
            } => {
                let position = usize::try_from(account_index)
                    .ok()
                    .filter(|position| *position < MANAGED_ACCOUNT_COUNT)
                    .ok_or(SecretError::UnsupportedAccount)?;
                let derived =
                    derive_exact_account(&entropy[..usize::from(*entropy_length)], account_index)?;
                if derived.metadata != accounts[position] {
                    return Err(SecretError::DerivationFailed);
                }
                Ok(derived.private_key)
            }
            Self::RawPrivateKey {
                private_key,
                account,
            } if account_index == 0 => {
                let copied = Zeroizing::new(**private_key);
                if address_from_private_key(&copied)? != account.address {
                    return Err(SecretError::DerivationFailed);
                }
                Ok(AccountPrivateKey(copied))
            }
            Self::RawPrivateKey { .. } => Err(SecretError::UnsupportedAccount),
        }
    }

    /// Returns an English phrase only for mnemonic-backed wallets.
    pub(crate) fn export_mnemonic(&self) -> Result<SecretExport, SecretError> {
        let Self::Mnemonic {
            entropy,
            entropy_length,
            ..
        } = self
        else {
            return Err(SecretError::ExportUnavailable);
        };
        let mnemonic =
            Mnemonic::from_entropy_in(Language::English, &entropy[..usize::from(*entropy_length)])
                .map_err(|_| SecretError::InvalidMnemonic)?;
        Ok(SecretExport {
            kind: SecretExportKind::Mnemonic,
            text: mnemonic_phrase(&mnemonic)?,
        })
    }

    /// Returns a lowercase 64-digit account private key.
    pub(crate) fn export_account_private_key(
        &self,
        account_index: u32,
    ) -> Result<SecretExport, SecretError> {
        let private_key = self.account_private_key(account_index)?;
        let mut text = Zeroizing::new(String::with_capacity(PRIVATE_KEY_BYTES * 2));
        let initial_capacity = text.capacity();
        encode_lower_hex(private_key.as_bytes(), &mut text);
        if text.len() != PRIVATE_KEY_BYTES * 2 || text.capacity() != initial_capacity {
            return Err(SecretError::CryptographicFailure);
        }
        Ok(SecretExport {
            kind: SecretExportKind::AccountPrivateKey,
            text,
        })
    }

    /// Copies secret material into a zeroizing fixed-size codec value.
    pub(crate) fn encoded_secret_material(&self) -> EncodedSecretMaterial {
        match self {
            Self::Mnemonic {
                entropy,
                entropy_length,
                ..
            } => EncodedSecretMaterial {
                source: WalletSource::Mnemonic,
                bytes: Zeroizing::new(**entropy),
                length: *entropy_length,
            },
            Self::RawPrivateKey { private_key, .. } => EncodedSecretMaterial {
                source: WalletSource::RawPrivateKey,
                bytes: Zeroizing::new(**private_key),
                length: PRIVATE_KEY_BYTES as u8,
            },
        }
    }
}

struct DerivedAccountSecret {
    private_key: AccountPrivateKey,
    metadata: AccountMetadata,
}

struct ExtendedPrivateKey {
    private_key: Zeroizing<[u8; PRIVATE_KEY_BYTES]>,
    chain_code: Zeroizing<[u8; 32]>,
}

impl ExtendedPrivateKey {
    fn from_seed(seed: &[u8]) -> Result<Self, SecretError> {
        if !(16..=64).contains(&seed.len()) {
            return Err(SecretError::DerivationFailed);
        }
        let output = hmac_sha512(BIP32_ROOT_KEY, seed)?;
        let mut private_key = Zeroizing::new([0_u8; PRIVATE_KEY_BYTES]);
        private_key.copy_from_slice(&output[..PRIVATE_KEY_BYTES]);
        validate_private_key(&private_key).map_err(|_| SecretError::DerivationFailed)?;
        let mut chain_code = Zeroizing::new([0_u8; 32]);
        chain_code.copy_from_slice(&output[PRIVATE_KEY_BYTES..]);
        Ok(Self {
            private_key,
            chain_code,
        })
    }

    fn derive_child(&self, child_number: u32) -> Result<Self, SecretError> {
        let mut data = Zeroizing::new([0_u8; 37]);
        if child_number & HARDENED_OFFSET != 0 {
            data[0] = 0;
            data[1..33].copy_from_slice(self.private_key.as_ref());
        } else {
            let mut parent = SecretKey::from_byte_array(*self.private_key)
                .map_err(|_| SecretError::DerivationFailed)?;
            let public = PublicKey::from_secret_key(&Secp256k1::new(), &parent);
            parent.non_secure_erase();
            data[..33].copy_from_slice(&public.serialize());
        }
        data[33..].copy_from_slice(&child_number.to_be_bytes());

        let output = hmac_sha512(self.chain_code.as_ref(), data.as_ref())?;
        let mut left = [0_u8; 32];
        left.copy_from_slice(&output[..32]);
        let mut scalar = Scalar::from_be_bytes(left).map_err(|_| {
            left.zeroize();
            SecretError::DerivationFailed
        })?;
        left.zeroize();
        let mut parent = SecretKey::from_byte_array(*self.private_key)
            .map_err(|_| SecretError::DerivationFailed)?;
        let child = parent.add_tweak(&scalar);
        parent.non_secure_erase();
        scalar.non_secure_erase();
        let mut child = child.map_err(|_| SecretError::DerivationFailed)?;
        let child_bytes = Zeroizing::new(child.secret_bytes());
        child.non_secure_erase();
        let mut chain_code = Zeroizing::new([0_u8; 32]);
        chain_code.copy_from_slice(&output[32..]);
        Ok(Self {
            private_key: child_bytes,
            chain_code,
        })
    }
}

fn derive_exact_account(
    entropy: &[u8],
    account_index: u32,
) -> Result<DerivedAccountSecret, SecretError> {
    if usize::try_from(account_index)
        .ok()
        .is_none_or(|index| index >= MANAGED_ACCOUNT_COUNT)
    {
        return Err(SecretError::UnsupportedAccount);
    }
    let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy)
        .map_err(|_| SecretError::InvalidMnemonic)?;
    let phrase = mnemonic_phrase(&mnemonic)?;
    if !phrase.is_ascii() {
        return Err(SecretError::InvalidMnemonic);
    }
    let mut seed = Zeroizing::new([0_u8; 64]);
    pbkdf2_hmac::<Sha512>(
        phrase.as_bytes(),
        BIP39_EMPTY_PASSPHRASE_SALT,
        BIP39_PBKDF2_ROUNDS,
        seed.as_mut(),
    );
    let mut current = ExtendedPrivateKey::from_seed(seed.as_ref())?;
    for component in DEFAULT_PATH_PREFIX {
        current = current.derive_child(component)?;
    }
    let derived = current.derive_child(account_index)?;
    let address = address_from_private_key(&derived.private_key)?;
    Ok(DerivedAccountSecret {
        private_key: AccountPrivateKey(derived.private_key),
        metadata: AccountMetadata {
            requested_index: account_index,
            actual_index: account_index,
            address,
        },
    })
}

fn validate_entropy_length(length: usize) -> Result<(), SecretError> {
    if matches!(length, 16 | 20 | 24 | 28 | 32) {
        Ok(())
    } else {
        Err(SecretError::InvalidMnemonic)
    }
}

fn mnemonic_phrase(mnemonic: &Mnemonic) -> Result<Zeroizing<String>, SecretError> {
    let word_count = mnemonic.word_count();
    let phrase_length = mnemonic
        .words()
        .try_fold(0_usize, |length, word| length.checked_add(word.len()))
        .and_then(|words_length| words_length.checked_add(word_count.saturating_sub(1)))
        .ok_or(SecretError::CryptographicFailure)?;
    let mut phrase = Zeroizing::new(String::with_capacity(phrase_length));
    let initial_capacity = phrase.capacity();
    for (index, word) in mnemonic.words().enumerate() {
        if index != 0 {
            phrase.push(' ');
        }
        phrase.push_str(word);
    }
    if phrase.len() != phrase_length || phrase.capacity() != initial_capacity {
        return Err(SecretError::CryptographicFailure);
    }
    Ok(phrase)
}

fn entropy_from_mnemonic(
    mnemonic: &Mnemonic,
) -> Result<(Zeroizing<[u8; MAX_ENTROPY_BYTES]>, usize), SecretError> {
    validate_import_word_count(mnemonic.word_count())?;
    let entropy_length = mnemonic
        .word_count()
        .checked_mul(4)
        .and_then(|bits| bits.checked_div(3))
        .ok_or(SecretError::InvalidMnemonic)?;
    validate_entropy_length(entropy_length)?;
    let entropy_bits = entropy_length
        .checked_mul(8)
        .ok_or(SecretError::InvalidMnemonic)?;
    let mut entropy = Zeroizing::new([0_u8; MAX_ENTROPY_BYTES]);
    let mut output_bit = 0_usize;
    for word_index in mnemonic.word_indices() {
        let mut word_index = Zeroizing::new(word_index);
        for shift in (0_u32..11).rev() {
            if output_bit == entropy_bits {
                break;
            }
            let bit = (*word_index >> shift) & 1;
            entropy[output_bit / 8] |= u8::try_from(bit)
                .map_err(|_| SecretError::InvalidMnemonic)?
                << (7 - (output_bit % 8));
            output_bit = output_bit
                .checked_add(1)
                .ok_or(SecretError::InvalidMnemonic)?;
        }
        word_index.zeroize();
    }
    if output_bit != entropy_bits || entropy[entropy_length..].iter().any(|byte| *byte != 0) {
        return Err(SecretError::InvalidMnemonic);
    }
    Ok((entropy, entropy_length))
}

fn validate_import_word_count(count: usize) -> Result<(), SecretError> {
    if matches!(count, 12 | 15 | 18 | 21 | 24) {
        Ok(())
    } else {
        Err(SecretError::InvalidMnemonic)
    }
}

fn validate_mnemonic_shape(phrase: &str) -> Result<(), SecretError> {
    if phrase.is_empty() || phrase.len() > MAX_MNEMONIC_INPUT_BYTES || !phrase.is_ascii() {
        return Err(SecretError::InvalidMnemonic);
    }
    let mut count = 0_usize;
    for word in phrase.split(' ') {
        if word.is_empty() || !word.bytes().all(|byte| byte.is_ascii_lowercase()) {
            return Err(SecretError::InvalidMnemonic);
        }
        count = count.checked_add(1).ok_or(SecretError::InvalidMnemonic)?;
    }
    validate_import_word_count(count)
}

fn validate_private_key(bytes: &[u8; PRIVATE_KEY_BYTES]) -> Result<(), SecretError> {
    let mut secret =
        SecretKey::from_byte_array(*bytes).map_err(|_| SecretError::InvalidPrivateKey)?;
    secret.non_secure_erase();
    Ok(())
}

fn address_from_private_key(
    private_key: &[u8; PRIVATE_KEY_BYTES],
) -> Result<EthereumAddress, SecretError> {
    let mut secret =
        SecretKey::from_byte_array(*private_key).map_err(|_| SecretError::InvalidPrivateKey)?;
    let public = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
    secret.non_secure_erase();
    let serialized = public.serialize_uncompressed();
    let digest = Keccak256::digest(&serialized[1..]);
    let mut address = [0_u8; 20];
    address.copy_from_slice(&digest[12..]);
    Ok(EthereumAddress::from_bytes(address))
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> Result<Zeroizing<[u8; 64]>, SecretError> {
    let mut mac = HmacSha512::new_from_slice(key).map_err(|_| SecretError::CryptographicFailure)?;
    mac.update(data);
    let mut finalized = mac.finalize().into_bytes();
    let mut output = Zeroizing::new([0_u8; 64]);
    output.copy_from_slice(finalized.as_slice());
    finalized.zeroize();
    Ok(output)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn encode_lower_hex(bytes: &[u8], output: &mut String) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EthereumAddress, ExtendedPrivateKey, MnemonicWordCount, SecretError, SecretExportKind,
        SecretInput, WalletSecret, WalletSource, address_from_private_key, encode_lower_hex,
    };

    const ZERO_ENTROPY_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn all_bip39_word_sizes_round_trip_and_preserve_exact_metadata() -> Result<(), SecretError> {
        for entropy_length in [16_usize, 20, 24, 28, 32] {
            let mut entropy = zeroize::Zeroizing::new([0_u8; 32]);
            for (index, byte) in entropy[..entropy_length].iter_mut().enumerate() {
                *byte = u8::try_from(index + entropy_length)
                    .map_err(|_| SecretError::InvalidMnemonic)?;
            }
            let wallet = WalletSecret::from_mnemonic_entropy(entropy, entropy_length)?;
            let phrase = wallet.export_mnemonic()?;
            let imported =
                WalletSecret::import_mnemonic(SecretInput::new(phrase.expose_secret().to_owned()))?;
            assert_eq!(wallet.word_count(), Some((entropy_length as u8 / 4) * 3));
            assert_eq!(imported.word_count(), wallet.word_count());
            assert_eq!(imported.source(), WalletSource::Mnemonic);
            for position in 0..2 {
                assert_eq!(imported.account(position), wallet.account(position));
                let metadata = imported
                    .account(position)
                    .ok_or(SecretError::DerivationFailed)?;
                assert_eq!(metadata.requested_index(), position as u32);
                assert_eq!(metadata.actual_index(), position as u32);
            }
        }
        Ok(())
    }

    #[test]
    fn generated_mnemonics_are_only_twelve_or_twenty_four_words() -> Result<(), SecretError> {
        let twelve = WalletSecret::generate_mnemonic(MnemonicWordCount::Twelve)?;
        let twenty_four = WalletSecret::generate_mnemonic(MnemonicWordCount::TwentyFour)?;
        assert_eq!(twelve.word_count(), Some(12));
        assert_eq!(twenty_four.word_count(), Some(24));
        assert_ne!(
            twelve.export_mnemonic()?.expose_secret(),
            twenty_four.export_mnemonic()?.expose_secret()
        );
        Ok(())
    }

    #[test]
    fn official_bip39_zero_entropy_phrases_cover_every_word_count() -> Result<(), SecretError> {
        let fixtures = [
            (
                16_usize,
                format!("{} about", "abandon ".repeat(11).trim_end()),
            ),
            (20, format!("{} address", "abandon ".repeat(14).trim_end())),
            (24, format!("{} agent", "abandon ".repeat(17).trim_end())),
            (28, format!("{} admit", "abandon ".repeat(20).trim_end())),
            (32, format!("{} art", "abandon ".repeat(23).trim_end())),
        ];
        for (entropy_length, expected_phrase) in fixtures {
            let wallet = WalletSecret::from_mnemonic_entropy(
                zeroize::Zeroizing::new([0_u8; 32]),
                entropy_length,
            )?;
            let export = wallet.export_mnemonic()?;
            assert_eq!(export.expose_secret(), expected_phrase);
            let imported = WalletSecret::import_mnemonic(SecretInput::new(expected_phrase))?;
            assert_eq!(imported.word_count(), wallet.word_count());
            assert_eq!(imported.account(0), wallet.account(0));
            assert_eq!(imported.account(1), wallet.account(1));
        }
        Ok(())
    }

    #[test]
    fn mnemonic_import_rejects_bad_checksum_spacing_language_and_bounds() {
        for invalid in [
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
            " abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "abandon  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "Abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        ] {
            assert!(matches!(
                WalletSecret::import_mnemonic(SecretInput::new(invalid.to_owned())),
                Err(SecretError::InvalidMnemonic)
            ));
        }
        assert!(matches!(
            WalletSecret::import_mnemonic(SecretInput::new("a".repeat(4_097))),
            Err(SecretError::InvalidMnemonic)
        ));
    }

    #[test]
    fn known_independent_ethereum_accounts_match_exact_empty_passphrase_paths()
    -> Result<(), SecretError> {
        let wallet =
            WalletSecret::import_mnemonic(SecretInput::new(ZERO_ENTROPY_MNEMONIC.to_owned()))?;
        assert_eq!(
            wallet
                .account(0)
                .ok_or(SecretError::DerivationFailed)?
                .address(),
            EthereumAddress::from_bytes([
                0x98, 0x58, 0xef, 0xfd, 0x23, 0x2b, 0x40, 0x33, 0xe4, 0x7d, 0x90, 0x00, 0x3d, 0x41,
                0xec, 0x34, 0xec, 0xae, 0xda, 0x94,
            ])
        );
        assert_eq!(
            wallet
                .account(1)
                .ok_or(SecretError::DerivationFailed)?
                .address(),
            EthereumAddress::from_bytes([
                0x6f, 0xac, 0x4d, 0x18, 0xc9, 0x12, 0x34, 0x3b, 0xf8, 0x6f, 0xa7, 0x04, 0x93, 0x64,
                0xdd, 0x4e, 0x42, 0x4a, 0xb9, 0xc0,
            ])
        );
        assert_eq!(
            wallet.export_account_private_key(0)?.expose_secret(),
            "1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727"
        );
        assert_eq!(
            wallet.export_account_private_key(1)?.expose_secret(),
            "9a983cb3d832fbde5ab49d692b7a8bf5b5d232479c99333d0fc8e1d21f1b55b6"
        );
        Ok(())
    }

    #[test]
    fn official_bip32_vector_one_matches_master_and_hardened_child_public_keys()
    -> Result<(), SecretError> {
        let mut seed = [0_u8; 16];
        for (index, byte) in seed.iter_mut().enumerate() {
            *byte = u8::try_from(index).map_err(|_| SecretError::DerivationFailed)?;
        }
        let master = ExtendedPrivateKey::from_seed(&seed)?;
        assert_eq!(
            compressed_public_hex(&master)?,
            "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2"
        );
        let child = master.derive_child(0x8000_0000)?;
        assert_eq!(
            compressed_public_hex(&child)?,
            "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56"
        );
        seed.zeroize();
        Ok(())
    }

    #[test]
    fn raw_key_import_is_strict_and_exports_lowercase_without_prefix() -> Result<(), SecretError> {
        let valid = format!("0x{}", "07".repeat(32));
        let wallet = WalletSecret::import_raw_private_key(SecretInput::new(valid))?;
        assert_eq!(wallet.source(), WalletSource::RawPrivateKey);
        assert_eq!(wallet.account_count(), 1);
        assert!(wallet.account(1).is_none());
        assert!(matches!(
            wallet.export_mnemonic(),
            Err(SecretError::ExportUnavailable)
        ));
        let export = wallet.export_account_private_key(0)?;
        assert_eq!(export.kind(), SecretExportKind::AccountPrivateKey);
        assert_eq!(export.expose_secret(), "07".repeat(32));
        let (kind, text) = export.into_zeroizing_text();
        assert_eq!(kind, SecretExportKind::AccountPrivateKey);
        assert_eq!(text.as_str(), "07".repeat(32));
        assert!(matches!(
            wallet.account_private_key(1),
            Err(SecretError::UnsupportedAccount)
        ));

        for invalid in [
            String::new(),
            "0X".to_owned() + &"07".repeat(32),
            "00".repeat(32),
            "07".repeat(31),
            format!(" {}", "07".repeat(32)),
            "gg".repeat(32),
        ] {
            assert!(matches!(
                WalletSecret::import_raw_private_key(SecretInput::new(invalid)),
                Err(SecretError::InvalidPrivateKey)
            ));
        }
        Ok(())
    }

    #[test]
    fn secret_debug_output_never_contains_inputs_or_exports() -> Result<(), SecretError> {
        let marker = "07".repeat(32);
        let input = SecretInput::new(marker.clone());
        assert!(!format!("{input:?}").contains(&marker));
        let wallet = WalletSecret::import_raw_private_key(input)?;
        let export = wallet.export_account_private_key(0)?;
        let private_key = wallet.account_private_key(0)?;
        let material = wallet.encoded_secret_material();
        for rendered in [
            format!("{wallet:?}"),
            format!("{export:?}"),
            format!("{private_key:?}"),
            format!("{material:?}"),
        ] {
            assert!(rendered.contains("[REDACTED]"));
            assert!(!rendered.contains(&marker));
        }
        Ok(())
    }

    #[test]
    fn raw_private_key_address_matches_independent_fixture() -> Result<(), SecretError> {
        let mut bytes = [0_u8; 32];
        bytes[31] = 1;
        let address = address_from_private_key(&bytes)?;
        assert_eq!(
            address,
            EthereumAddress::from_bytes([
                0x7e, 0x5f, 0x45, 0x52, 0x09, 0x1a, 0x69, 0x12, 0x5d, 0x5d, 0xfc, 0xb7, 0xb8, 0xc2,
                0x65, 0x90, 0x29, 0x39, 0x5b, 0xdf,
            ])
        );
        let mut encoded = String::new();
        encode_lower_hex(&bytes, &mut encoded);
        assert_eq!(encoded, format!("{}1", "0".repeat(63)));
        Ok(())
    }

    fn compressed_public_hex(key: &ExtendedPrivateKey) -> Result<String, SecretError> {
        let mut secret = SecretKey::from_byte_array(*key.private_key)
            .map_err(|_| SecretError::DerivationFailed)?;
        let public = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
        secret.non_secure_erase();
        Ok(public.to_string())
    }

    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use zeroize::Zeroize as _;
}
