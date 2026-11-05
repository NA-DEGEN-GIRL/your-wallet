//! BIP39 with the embedded English word list (D6, D8, D9; spec/02 §2).
//!
//! Own implementation: entropy ↔ word indices (11 bits, MSB first, checksum = first ENT/32 bits
//! of SHA-256(entropy)), a strict parser (no normalization), and the PBKDF2-HMAC-SHA512 seed.
//! Ported from `archive/spec-v2.4:crates/secret-core/src/mnemonic.rs` with the `bip39` crate
//! and NFKD removed.
#![deny(clippy::indexing_slicing)]

use core::fmt;
use std::sync::OnceLock;

use sha2::{Digest, Sha256, Sha512};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

use crate::entropy::{OsRandom, RandomSource, random_below_with, random_secret32_with};
use crate::error::KeyError;
use crate::password::Bip39Passphrase;
use crate::secret::{SecretBytes, SecretString};

/// Words asked by the backup confirmation (spec/02 §8.3).
pub const BACKUP_WORDS: usize = 4;
/// Longest BIP39 English word.
const MAX_BACKUP_WORD: usize = 8;

/// Picks [`BACKUP_WORDS`] distinct 1-based positions of a `words`-word phrase (partial
/// Fisher–Yates over `random_below`), ascending.
pub(crate) fn backup_positions_with(
    rng: &mut impl RandomSource,
    words: usize,
) -> Result<[u8; BACKUP_WORDS], KeyError> {
    if !(BACKUP_WORDS..=24).contains(&words) {
        return Err(KeyError::Internal);
    }
    let mut candidates = [0_u8; 24];
    for (index, slot) in candidates.iter_mut().enumerate() {
        *slot = u8::try_from(index).map_err(|_| KeyError::Internal)?;
    }
    for offset in 0..BACKUP_WORDS {
        let remaining = u32::try_from(words.checked_sub(offset).ok_or(KeyError::Internal)?)
            .map_err(|_| KeyError::Internal)?;
        let pick =
            usize::try_from(random_below_with(rng, remaining)?).map_err(|_| KeyError::Internal)?;
        candidates.swap(
            offset,
            offset
                .checked_add(pick)
                .filter(|index| *index < words)
                .ok_or(KeyError::Internal)?,
        );
    }
    let mut positions = [0_u8; BACKUP_WORDS];
    for (position, candidate) in positions.iter_mut().zip(candidates) {
        *position = candidate.checked_add(1).ok_or(KeyError::Internal)?;
    }
    positions.sort_unstable();
    Ok(positions)
}

/// PBKDF2 iteration count for the seed.
pub const BIP39_PBKDF2_ROUNDS: u32 = 2_048;
/// Seed salt prefix; the passphrase bytes follow.
pub const BIP39_SALT_PREFIX: &[u8] = b"mnemonic";
/// Longest accepted phrase in bytes (24 words are at most 215 bytes).
pub const MAX_MNEMONIC_INPUT_BYTES: usize = 256;
/// Longest accepted passphrase in bytes.
pub const MAX_PASSPHRASE_BYTES: usize = 256;

const WORDLIST_TEXT: &str = include_str!("english.txt");
const WORDLIST_LEN: usize = 2_048;
/// Entropy (≤ 32 bytes) followed by the checksum byte.
const BIT_BUFFER_LEN: usize = 33;

static WORDLIST: OnceLock<Option<Box<[&'static str; WORDLIST_LEN]>>> = OnceLock::new();

fn split_wordlist() -> Option<Box<[&'static str; WORDLIST_LEN]>> {
    let words: Box<[&'static str]> = WORDLIST_TEXT.split_terminator('\n').collect();
    words.try_into().ok()
}

/// The 2048 English words, split once on first use.
pub(crate) fn wordlist() -> Result<&'static [&'static str; WORDLIST_LEN], KeyError> {
    WORDLIST
        .get_or_init(split_wordlist)
        .as_deref()
        .ok_or(KeyError::Internal)
}

/// Whether `word` is in the English list (binary search, spec/02 §2.1). Used by the word-by-word
/// mnemonic entry grid (spec/04 §4.2 W05) before the whole phrase is parsed.
#[must_use]
pub fn is_word(word: &str) -> bool {
    wordlist().is_ok_and(|list| {
        list.binary_search_by(|candidate| candidate.as_bytes().cmp(word.as_bytes()))
            .is_ok()
    })
}

/// Supported mnemonic lengths (entropy 16/20/24/28/32 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WordCount {
    /// 12 words, 128-bit entropy.
    W12,
    /// 15 words, 160-bit entropy.
    W15,
    /// 18 words, 192-bit entropy.
    W18,
    /// 21 words, 224-bit entropy.
    W21,
    /// 24 words, 256-bit entropy.
    W24,
}

impl WordCount {
    /// Number of words.
    #[must_use]
    pub const fn words(self) -> usize {
        match self {
            Self::W12 => 12,
            Self::W15 => 15,
            Self::W18 => 18,
            Self::W21 => 21,
            Self::W24 => 24,
        }
    }

    /// Entropy length in bytes.
    #[must_use]
    pub const fn entropy_len(self) -> usize {
        match self {
            Self::W12 => 16,
            Self::W15 => 20,
            Self::W18 => 24,
            Self::W21 => 28,
            Self::W24 => 32,
        }
    }

    const fn from_entropy_len(len: usize) -> Option<Self> {
        match len {
            16 => Some(Self::W12),
            20 => Some(Self::W15),
            24 => Some(Self::W18),
            28 => Some(Self::W21),
            32 => Some(Self::W24),
            _ => None,
        }
    }

    const fn from_words(words: usize) -> Option<Self> {
        match words {
            12 => Some(Self::W12),
            15 => Some(Self::W15),
            18 => Some(Self::W18),
            21 => Some(Self::W21),
            24 => Some(Self::W24),
            _ => None,
        }
    }

    /// Checksum bits = ENT / 32.
    const fn checksum_bits(self) -> u32 {
        match self {
            Self::W12 => 4,
            Self::W15 => 5,
            Self::W18 => 6,
            Self::W21 => 7,
            Self::W24 => 8,
        }
    }
}

/// A BIP39 mnemonic held as its entropy. Secret: no `Clone`/`Display`, redacted `Debug`.
pub struct Mnemonic {
    entropy: Zeroizing<[u8; 32]>,
    count: WordCount,
}

impl fmt::Debug for Mnemonic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Mnemonic([REDACTED])")
    }
}

fn get_bit(buffer: &[u8; BIT_BUFFER_LEN], bit: usize) -> u16 {
    let byte = buffer.get(bit / 8).copied().unwrap_or(0);
    u16::from((byte >> (7 - (bit % 8))) & 1)
}

fn set_bit(buffer: &mut [u8; BIT_BUFFER_LEN], bit: usize) {
    if let Some(byte) = buffer.get_mut(bit / 8) {
        *byte |= 0x80 >> (bit % 8);
    }
}

impl Mnemonic {
    /// Generates a 24-word mnemonic; the entropy is the first draw of `rng` (D9).
    pub(crate) fn generate_with_rng(rng: &mut impl RandomSource) -> Result<Self, KeyError> {
        let entropy = random_secret32_with(rng)?;
        Ok(Self {
            entropy,
            count: WordCount::W24,
        })
    }

    /// Generates a new 24-word mnemonic from the OS random source (D9): the mnemonic of a
    /// `YubiKey` wallet, which is shown once and never stored (spec/10 §7.1-1).
    ///
    /// # Errors
    ///
    /// [`KeyError::RandomnessUnavailable`].
    pub fn generate() -> Result<Self, KeyError> {
        Self::generate_with_rng(&mut OsRandom)
    }

    /// Four distinct 1-based word positions, ascending, for the backup confirmation of a
    /// mnemonic held in memory (spec/02 §8.3, the same draw as `Vault::backup_challenge`).
    ///
    /// # Errors
    ///
    /// [`KeyError::RandomnessUnavailable`], [`KeyError::Internal`].
    pub fn backup_positions(&self) -> Result<[u8; BACKUP_WORDS], KeyError> {
        backup_positions_with(&mut OsRandom, self.count.words())
    }

    /// Whether the answers are the words at `positions` (spec/02 §8.3): every answer must be
    /// 1–8 lowercase ASCII letters, and the four comparisons run in constant time and are
    /// decided once (as `Vault::confirm_backup`).
    ///
    /// # Errors
    ///
    /// [`KeyError::Internal`] for a position outside the phrase.
    pub fn backup_words_match(
        &self,
        positions: [u8; BACKUP_WORDS],
        answers: [&str; BACKUP_WORDS],
    ) -> Result<bool, KeyError> {
        let well_formed = answers.iter().all(|word| {
            (1..=MAX_BACKUP_WORD).contains(&word.len())
                && word.bytes().all(|b| b.is_ascii_lowercase())
        });
        if !well_formed {
            return Ok(false);
        }
        let mut all = Choice::from(1);
        for (position, answer) in positions.iter().zip(answers) {
            let expected = self.word_at(*position)?;
            all &= expected.as_bytes().ct_eq(answer.as_bytes());
        }
        Ok(all.unwrap_u8() == 1)
    }

    /// Builds a mnemonic from 16/20/24/28/32 bytes of entropy.
    ///
    /// # Errors
    ///
    /// [`KeyError::InvalidEntropyLength`] for any other length.
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, KeyError> {
        let count =
            WordCount::from_entropy_len(entropy.len()).ok_or(KeyError::InvalidEntropyLength)?;
        let mut stored = Zeroizing::new([0_u8; 32]);
        stored
            .get_mut(..entropy.len())
            .ok_or(KeyError::InvalidEntropyLength)?
            .copy_from_slice(entropy);
        Ok(Self {
            entropy: stored,
            count,
        })
    }

    /// Strictly parses a phrase: lowercase ASCII words separated by single spaces (spec/02 §2.4).
    ///
    /// # Errors
    ///
    /// The first failing check: [`KeyError::MnemonicFormat`], [`KeyError::MnemonicWordCount`],
    /// [`KeyError::MnemonicUnknownWord`] or [`KeyError::MnemonicChecksum`].
    pub fn parse(phrase: &str) -> Result<Self, KeyError> {
        let bytes = phrase.as_bytes();
        if bytes.len() > MAX_MNEMONIC_INPUT_BYTES
            || !bytes.iter().all(|b| b.is_ascii_lowercase() || *b == b' ')
        {
            return Err(KeyError::MnemonicFormat);
        }
        if bytes.first() == Some(&b' ') || bytes.last() == Some(&b' ') || phrase.contains("  ") {
            return Err(KeyError::MnemonicFormat);
        }
        let words_in = if phrase.is_empty() {
            0
        } else {
            phrase.split(' ').count()
        };
        let count = WordCount::from_words(words_in).ok_or(KeyError::MnemonicWordCount)?;
        let list = wordlist()?;
        let mut indices = Zeroizing::new([0_u16; 24]);
        for (position, (word, slot)) in phrase.split(' ').zip(indices.iter_mut()).enumerate() {
            let index =
                list.binary_search_by(|candidate| candidate.as_bytes().cmp(word.as_bytes()));
            let Ok(index) = index else {
                let position =
                    u8::try_from(position.saturating_add(1)).map_err(|_| KeyError::Internal)?;
                return Err(KeyError::MnemonicUnknownWord { position });
            };
            *slot = u16::try_from(index).map_err(|_| KeyError::Internal)?;
        }
        let mut bits = Zeroizing::new([0_u8; BIT_BUFFER_LEN]);
        for (word_index, value) in indices.iter().take(count.words()).enumerate() {
            for offset in 0..11 {
                if (value >> (10 - offset)) & 1 == 1 {
                    set_bit(&mut bits, word_index * 11 + offset);
                }
            }
        }
        let entropy_len = count.entropy_len();
        let entropy = bits.get(..entropy_len).ok_or(KeyError::Internal)?;
        let shift = 8 - count.checksum_bits();
        let expected = Sha256::digest(entropy).first().copied().unwrap_or(0) >> shift;
        let actual = bits.get(entropy_len).copied().unwrap_or(0) >> shift;
        if expected != actual {
            return Err(KeyError::MnemonicChecksum);
        }
        Self::from_entropy(entropy)
    }

    /// The number of words.
    #[must_use]
    pub const fn word_count(&self) -> WordCount {
        self.count
    }

    /// The entropy bytes.
    pub(crate) fn entropy(&self) -> &[u8] {
        self.entropy.get(..self.count.entropy_len()).unwrap_or(&[])
    }

    fn bit_buffer(&self) -> Zeroizing<[u8; BIT_BUFFER_LEN]> {
        let entropy = self.entropy();
        let mut bits = Zeroizing::new([0_u8; BIT_BUFFER_LEN]);
        for (slot, byte) in bits.iter_mut().zip(entropy) {
            *slot = *byte;
        }
        let mut digest = Sha256::digest(entropy);
        if let Some(slot) = bits.get_mut(entropy.len()) {
            *slot = digest.first().copied().unwrap_or(0);
        }
        digest.as_mut_slice().zeroize();
        bits
    }

    fn index_at(bits: &[u8; BIT_BUFFER_LEN], word: usize) -> usize {
        let start = word * 11;
        let mut value = 0_usize;
        for offset in 0..11 {
            value = (value << 1) | usize::from(get_bit(bits, start + offset));
        }
        value
    }

    /// The phrase: words joined by single 0x20 bytes, in a redacting [`SecretString`] whose
    /// capacity is computed before the first push (no reallocation copies).
    ///
    /// # Errors
    ///
    /// `KeyError::Internal` when the word list or the buffer fails (never an empty or partial
    /// phrase, which would derive a different seed).
    pub fn phrase(&self) -> Result<SecretString, KeyError> {
        let list = wordlist()?;
        let bits = self.bit_buffer();
        let words = self.count.words();
        let length = (0..words)
            .filter_map(|word| list.get(Self::index_at(&bits, word)))
            .map(|word| word.len())
            .sum::<usize>()
            .saturating_add(words.saturating_sub(1));
        let mut phrase = SecretString::with_capacity(length);
        for word in 0..words {
            // The capacity is exact, so neither push can fail.
            if word != 0 {
                phrase.push_str(" ").map_err(|_| KeyError::Internal)?;
            }
            let text = list
                .get(Self::index_at(&bits, word))
                .copied()
                .ok_or(KeyError::Internal)?;
            phrase.push_str(text).map_err(|_| KeyError::Internal)?;
        }
        Ok(phrase)
    }

    /// The word at a 1-based position.
    pub(crate) fn word_at(&self, position: u8) -> Result<&'static str, KeyError> {
        let index = usize::from(position)
            .checked_sub(1)
            .ok_or(KeyError::Internal)?;
        if index >= self.count.words() {
            return Err(KeyError::Internal);
        }
        let bits = self.bit_buffer();
        wordlist()?
            .get(Self::index_at(&bits, index))
            .copied()
            .ok_or(KeyError::Internal)
    }

    /// `PBKDF2-HMAC-SHA512(phrase, "mnemonic" ‖ passphrase, 2048, 64)` (spec/02 §2.5), in a
    /// redacting [`SecretBytes`].
    ///
    /// # Errors
    ///
    /// `KeyError::Internal` from [`Self::phrase`].
    pub fn to_seed(&self, passphrase: &Bip39Passphrase) -> Result<SecretBytes<64>, KeyError> {
        let phrase = self.phrase()?;
        let pass = passphrase.as_bytes();
        let mut salt = Zeroizing::new(Vec::with_capacity(
            BIP39_SALT_PREFIX.len().saturating_add(pass.len()),
        ));
        salt.extend_from_slice(BIP39_SALT_PREFIX);
        salt.extend_from_slice(pass);
        let mut seed = Zeroizing::new([0_u8; 64]);
        pbkdf2::pbkdf2_hmac::<Sha512>(
            phrase.expose().as_bytes(),
            &salt,
            BIP39_PBKDF2_ROUNDS,
            seed.as_mut(),
        );
        Ok(SecretBytes::new(&mut seed))
    }
}

#[cfg(test)]
mod tests;
