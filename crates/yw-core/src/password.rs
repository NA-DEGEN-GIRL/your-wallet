//! Vault password and BIP39 passphrase (D8, spec/02 §2.2, §10.1).
//!
//! Both are printable ASCII (0x20–0x7E), kept byte-for-byte (case and spaces preserved, no
//! normalization, no trimming). Printable ASCII has no canonical or compatibility
//! decomposition, so NFKD would be the identity and the BIP39 seed stays standard.

use core::fmt;

use zeroize::Zeroizing;

use crate::error::KeyError;

/// Minimum vault password length in bytes.
pub const PASSWORD_MIN: usize = 12;
/// Maximum vault password length in bytes.
pub const PASSWORD_MAX: usize = 128;
/// Maximum BIP39 passphrase length in bytes (`bip39::MAX_PASSPHRASE_BYTES`).
const PASSPHRASE_MAX: usize = crate::bip39::MAX_PASSPHRASE_BYTES;

const fn printable(byte: u8) -> bool {
    matches!(byte, 0x20..=0x7e)
}

fn copy_exact(input: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(input.len()));
    bytes.extend_from_slice(input);
    bytes
}

/// The vault password: 12–128 bytes, each 0x20–0x7E. Strength checks are not done here.
pub struct VaultPassword(Zeroizing<Vec<u8>>);

impl VaultPassword {
    /// Validates and copies the password bytes.
    ///
    /// # Errors
    ///
    /// [`KeyError::PasswordInvalidChar`], [`KeyError::PasswordTooShort`] or
    /// [`KeyError::PasswordTooLong`].
    pub fn new(input: &[u8]) -> Result<Self, KeyError> {
        if !input.iter().copied().all(printable) {
            return Err(KeyError::PasswordInvalidChar);
        }
        if input.len() < PASSWORD_MIN {
            return Err(KeyError::PasswordTooShort);
        }
        if input.len() > PASSWORD_MAX {
            return Err(KeyError::PasswordTooLong);
        }
        Ok(Self(copy_exact(input)))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for VaultPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultPassword([REDACTED])")
    }
}

/// An optional BIP39 passphrase: 0–256 bytes, each 0x20–0x7E, used exactly as entered.
pub struct Bip39Passphrase(Zeroizing<Vec<u8>>);

impl Bip39Passphrase {
    /// Validates and copies the passphrase.
    ///
    /// # Errors
    ///
    /// [`KeyError::PassphraseTooLong`] above 256 bytes, [`KeyError::PassphraseInvalidChar`] for a
    /// byte outside 0x20–0x7E.
    pub fn new(input: &str) -> Result<Self, KeyError> {
        Self::from_bytes(input.as_bytes())
    }

    pub(crate) fn from_bytes(input: &[u8]) -> Result<Self, KeyError> {
        if input.len() > PASSPHRASE_MAX {
            return Err(KeyError::PassphraseTooLong);
        }
        if !input.iter().copied().all(printable) {
            return Err(KeyError::PassphraseInvalidChar);
        }
        Ok(Self(copy_exact(input)))
    }

    /// The empty passphrase.
    #[must_use]
    pub fn empty() -> Self {
        Self(Zeroizing::new(Vec::new()))
    }

    /// Whether the passphrase is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Bip39Passphrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Bip39Passphrase([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::{Bip39Passphrase, KeyError, VaultPassword};

    #[test]
    fn password_rules_v5() {
        assert_eq!(
            VaultPassword::new(&[b'a'; 11]).err(),
            Some(KeyError::PasswordTooShort)
        );
        assert_eq!(
            VaultPassword::new(&[b'a'; 129]).err(),
            Some(KeyError::PasswordTooLong)
        );
        assert_eq!(
            VaultPassword::new(b"abcdefghijkl\x7f").err(),
            Some(KeyError::PasswordInvalidChar)
        );
        assert_eq!(
            VaultPassword::new(b"abcdefghijkl\x1f").err(),
            Some(KeyError::PasswordInvalidChar)
        );
        assert_eq!(
            VaultPassword::new("abcdefghijkl\u{e9}".as_bytes()).err(),
            Some(KeyError::PasswordInvalidChar)
        );
        assert_eq!(
            VaultPassword::new(&[b'a'; 12]).unwrap().as_bytes(),
            &[b'a'; 12]
        );
        assert_eq!(
            VaultPassword::new(&[b'~'; 128]).unwrap().as_bytes().len(),
            128
        );
        let spaced = VaultPassword::new(b"  Mixed Case  ").unwrap();
        assert_eq!(spaced.as_bytes(), b"  Mixed Case  ");
        assert_eq!(format!("{spaced:?}"), "VaultPassword([REDACTED])");
    }

    #[test]
    fn passphrase_rules_v6() {
        assert_eq!(
            Bip39Passphrase::new(&"a".repeat(256))
                .unwrap()
                .as_bytes()
                .len(),
            256
        );
        assert_eq!(
            Bip39Passphrase::new(&"a".repeat(257)).err(),
            Some(KeyError::PassphraseTooLong)
        );
        assert_eq!(
            Bip39Passphrase::new("a\u{7f}").err(),
            Some(KeyError::PassphraseInvalidChar)
        );
        assert_eq!(
            Bip39Passphrase::new("a\u{1f}").err(),
            Some(KeyError::PassphraseInvalidChar)
        );
        assert_eq!(
            Bip39Passphrase::new("\u{e9}").err(),
            Some(KeyError::PassphraseInvalidChar)
        );
        assert!(Bip39Passphrase::new("").unwrap().is_empty());
        assert!(Bip39Passphrase::empty().is_empty());
        let spaced = Bip39Passphrase::new(" TREZOR").unwrap();
        assert_eq!(spaced.as_bytes(), b" TREZOR");
        assert!(!format!("{spaced:?}").contains("TREZOR"));
    }
}
