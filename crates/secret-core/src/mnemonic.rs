use core::fmt;

use bip39::{Language, Mnemonic};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::bip32::ExtendedPrivateKey;
use crate::{AccountIndex, DerivedAccount, SecretError};

const BIP39_PBKDF2_ROUNDS: u32 = 2_048;
const MAX_SESSION_PASSPHRASE_BYTES: usize = 1_024;
const MAX_SESSION_PASSPHRASE_INPUT_BYTES: usize = MAX_SESSION_PASSPHRASE_BYTES * 4;
const MAX_MNEMONIC_INPUT_BYTES: usize = 4_096;
const BIP39_SALT_PREFIX: &[u8] = b"mnemonic";

/// Supported mnemonic sizes for newly created wallets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MnemonicWordCount {
    /// A 128-bit entropy mnemonic.
    Twelve,
    /// A 256-bit entropy mnemonic.
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

/// Validated BIP-39 entropy. The entropy is secret and zeroized on drop.
pub struct MnemonicEntropy {
    entropy: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for MnemonicEntropy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MnemonicEntropy([REDACTED])")
    }
}

impl MnemonicEntropy {
    /// Generates entropy using the operating-system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns an error when operating-system randomness is unavailable or the
    /// generated entropy cannot be represented as an English BIP-39 mnemonic.
    pub fn generate(words: MnemonicWordCount) -> Result<Self, SecretError> {
        let mut entropy = Zeroizing::new(vec![0_u8; words.entropy_bytes()]);
        getrandom::fill(entropy.as_mut_slice()).map_err(|_| SecretError::RandomnessUnavailable)?;
        Self::from_entropy(entropy.as_slice())
    }

    /// Imports validated BIP-39 entropy of 128, 160, 192, 224, or 256 bits.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::InvalidMnemonic`] for unsupported entropy lengths.
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, SecretError> {
        validate_entropy_length(entropy.len())?;
        Mnemonic::from_entropy_in(Language::English, entropy)
            .map_err(|_| SecretError::InvalidMnemonic)?;
        Ok(Self {
            entropy: Zeroizing::new(entropy.to_vec()),
        })
    }

    /// Imports an English BIP-39 phrase and validates its word count/checksum.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::InvalidMnemonic`] for a non-English word, invalid
    /// checksum, unsupported word count, or malformed spacing.
    pub fn import_english(phrase: &str) -> Result<Self, SecretError> {
        if phrase.len() > MAX_MNEMONIC_INPUT_BYTES {
            return Err(SecretError::InvalidMnemonic);
        }
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|_| SecretError::InvalidMnemonic)?;
        validate_import_word_count(mnemonic.word_count())?;
        let entropy_length = mnemonic
            .word_count()
            .checked_mul(4)
            .and_then(|bits| bits.checked_div(3))
            .ok_or(SecretError::InvalidMnemonic)?;
        let entropy_bits = entropy_length
            .checked_mul(8)
            .ok_or(SecretError::InvalidMnemonic)?;
        let mut entropy = Zeroizing::new([0_u8; 32]);
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
        if output_bit != entropy_bits {
            return Err(SecretError::InvalidMnemonic);
        }
        Self::from_entropy(&entropy[..entropy_length])
    }

    /// Produces the English backup phrase for display by the one-shot secret UI.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::InvalidMnemonic`] if the in-memory entropy
    /// invariant is violated.
    pub fn reveal_phrase(&self) -> Result<SecretPhrase, SecretError> {
        let mnemonic = Mnemonic::from_entropy_in(Language::English, self.entropy.as_slice())
            .map_err(|_| SecretError::InvalidMnemonic)?;
        let word_count = mnemonic.word_count();
        let phrase_length = mnemonic
            .words()
            .try_fold(0_usize, |length, word| length.checked_add(word.len()))
            .and_then(|words_length| words_length.checked_add(word_count.saturating_sub(1)))
            .ok_or(SecretError::BoundsExceeded)?;
        let mut words = Zeroizing::new(String::with_capacity(phrase_length));
        let initial_capacity = words.capacity();
        for (index, word) in mnemonic.words().enumerate() {
            if index != 0 {
                words.push(' ');
            }
            words.push_str(word);
        }
        if words.len() != phrase_length || words.capacity() != initial_capacity {
            return Err(SecretError::CryptographicFailure);
        }
        Ok(SecretPhrase { words })
    }

    /// Derives the default Ethereum account path, skipping only invalid child
    /// scalars and returning the actual path/index used.
    ///
    /// # Errors
    ///
    /// Returns an error when BIP-39 seed derivation, BIP-32 child derivation, or
    /// `secp256k1` public-key derivation fails.
    pub fn derive_ethereum_account(
        &self,
        passphrase: &SessionPassphrase,
        requested_index: AccountIndex,
    ) -> Result<DerivedAccount, SecretError> {
        let phrase = self.reveal_phrase()?;
        if !phrase.words.is_ascii() {
            return Err(SecretError::InvalidMnemonic);
        }
        let mut salt = Zeroizing::new(Vec::with_capacity(
            BIP39_SALT_PREFIX.len() + passphrase.normalized_utf8.len(),
        ));
        let initial_salt_capacity = salt.capacity();
        salt.extend_from_slice(BIP39_SALT_PREFIX);
        salt.extend_from_slice(passphrase.normalized_utf8.as_slice());
        if salt.capacity() != initial_salt_capacity {
            return Err(SecretError::CryptographicFailure);
        }

        let mut seed = Zeroizing::new([0_u8; 64]);
        pbkdf2_hmac::<Sha512>(
            phrase.words.as_bytes(),
            salt.as_slice(),
            BIP39_PBKDF2_ROUNDS,
            seed.as_mut(),
        );

        let root = ExtendedPrivateKey::from_seed(seed.as_ref())?;
        root.derive_default_ethereum_account(requested_index)
    }

    pub(crate) fn expose_entropy(&self) -> &[u8] {
        self.entropy.as_slice()
    }
}

/// One-time BIP-39 backup phrase value, zeroized on drop.
pub struct SecretPhrase {
    words: Zeroizing<String>,
}

impl fmt::Debug for SecretPhrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretPhrase([REDACTED])")
    }
}

impl SecretPhrase {
    /// Exposes words to the trusted one-shot secret-output path.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        self.words.as_str()
    }
}

/// A BIP-39 passphrase held only for the current unlocked session.
pub struct SessionPassphrase {
    normalized_utf8: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for SessionPassphrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionPassphrase([REDACTED])")
    }
}

impl SessionPassphrase {
    /// Applies BIP-39 NFKD normalization and enforces the wallet's input bound.
    ///
    /// # Errors
    ///
    /// Returns an error for control characters or a normalized value exceeding
    /// 1,024 UTF-8 bytes.
    pub fn new(input: &str) -> Result<Self, SecretError> {
        if input.len() > MAX_SESSION_PASSPHRASE_INPUT_BYTES || input.chars().any(char::is_control) {
            return Err(SecretError::InvalidPasswordProfile);
        }
        let normalized_length = input
            .nfkd()
            .try_fold(0_usize, |length, character| {
                length.checked_add(character.len_utf8())
            })
            .ok_or(SecretError::BoundsExceeded)?;
        if normalized_length > MAX_SESSION_PASSPHRASE_BYTES {
            return Err(SecretError::BoundsExceeded);
        }
        let mut normalized_utf8 = Zeroizing::new(Vec::with_capacity(normalized_length));
        let initial_capacity = normalized_utf8.capacity();
        for character in input.nfkd() {
            let mut encoded = [0_u8; 4];
            let encoded_length = character.encode_utf8(&mut encoded).len();
            normalized_utf8.extend_from_slice(&encoded[..encoded_length]);
            encoded.zeroize();
        }
        if normalized_utf8.len() != normalized_length
            || normalized_utf8.capacity() != initial_capacity
        {
            return Err(SecretError::CryptographicFailure);
        }
        Ok(Self { normalized_utf8 })
    }

    /// Creates an empty BIP-39 passphrase.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            normalized_utf8: Zeroizing::new(Vec::new()),
        }
    }

    /// Whether this session has a non-empty BIP-39 passphrase.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.normalized_utf8.is_empty()
    }
}

fn validate_entropy_length(length: usize) -> Result<(), SecretError> {
    if matches!(length, 16 | 20 | 24 | 28 | 32) {
        Ok(())
    } else {
        Err(SecretError::InvalidMnemonic)
    }
}

fn validate_import_word_count(words: usize) -> Result<(), SecretError> {
    if matches!(words, 12 | 15 | 18 | 21 | 24) {
        Ok(())
    } else {
        Err(SecretError::InvalidMnemonic)
    }
}

#[cfg(test)]
mod tests {
    use super::{MnemonicEntropy, MnemonicWordCount, SessionPassphrase};
    use crate::{AccountIndex, SecretError};

    #[test]
    fn accepts_all_standard_entropy_sizes() -> Result<(), SecretError> {
        for size in [16_usize, 20, 24, 28, 32] {
            let byte = u8::try_from(size).map_err(|_| SecretError::BoundsExceeded)?;
            let fixture = vec![byte; size];
            let mnemonic = MnemonicEntropy::from_entropy(&fixture)?;
            let phrase = mnemonic.reveal_phrase()?;
            let imported = MnemonicEntropy::import_english(phrase.expose_secret())?;
            assert_eq!(imported.expose_entropy(), fixture.as_slice());
        }
        Ok(())
    }

    #[test]
    fn rejects_nonstandard_entropy_sizes() {
        assert!(MnemonicEntropy::from_entropy(&[7_u8; 17]).is_err());
    }

    #[test]
    fn creates_supported_random_strengths() -> Result<(), SecretError> {
        let twelve = MnemonicEntropy::generate(MnemonicWordCount::Twelve)?;
        let twenty_four = MnemonicEntropy::generate(MnemonicWordCount::TwentyFour)?;
        assert_eq!(
            twelve.reveal_phrase()?.expose_secret().split(' ').count(),
            12
        );
        assert_eq!(
            twenty_four
                .reveal_phrase()?
                .expose_secret()
                .split(' ')
                .count(),
            24
        );
        Ok(())
    }

    #[test]
    fn deterministic_account_derivation_round_trips() -> Result<(), SecretError> {
        let fixture = [23_u8; 16];
        let mnemonic = MnemonicEntropy::from_entropy(&fixture)?;
        let passphrase = SessionPassphrase::new("session-only-value")?;
        let first = mnemonic.derive_ethereum_account(&passphrase, AccountIndex::new(0)?)?;
        let second = mnemonic.derive_ethereum_account(&passphrase, AccountIndex::new(0)?)?;
        assert_eq!(first.address(), second.address());
        assert_eq!(first.actual_index(), second.actual_index());
        Ok(())
    }
}
