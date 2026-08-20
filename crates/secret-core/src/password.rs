use core::fmt;

use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

use crate::SecretError;

const MIN_PASSWORD_SCALARS: usize = 12;
const MAX_PASSWORD_UTF8_BYTES: usize = 1_024;
const MAX_PASSWORD_INPUT_BYTES: usize = MAX_PASSWORD_UTF8_BYTES * 4;

/// A password after applying the vault's fixed Unicode profile.
///
/// The profile maps Unicode space separators to ASCII space, applies NFC,
/// preserves case, and rejects control/noncharacter code points. It is a narrow,
/// frozen profile inspired by PRECIS `OpaqueString` rather than locale-sensitive
/// operating-system normalization.
pub struct VaultPassword {
    normalized_utf8: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for VaultPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VaultPassword([REDACTED])")
    }
}

impl VaultPassword {
    /// Applies and validates the fixed password profile.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::InvalidPasswordProfile`] when the normalized
    /// value is too short, too long, or contains a prohibited scalar.
    pub fn new(input: &str) -> Result<Self, SecretError> {
        if input.len() > MAX_PASSWORD_INPUT_BYTES {
            return Err(SecretError::InvalidPasswordProfile);
        }
        let mapped_length = input
            .chars()
            .map(map_space)
            .try_fold(0_usize, |length, character| {
                length.checked_add(character.len_utf8())
            })
            .ok_or(SecretError::InvalidPasswordProfile)?;
        let mut mapped = Zeroizing::new(String::with_capacity(mapped_length));
        let mapped_capacity = mapped.capacity();
        mapped.extend(input.chars().map(map_space));
        if mapped.len() != mapped_length || mapped.capacity() != mapped_capacity {
            return Err(SecretError::CryptographicFailure);
        }

        let normalized_length = mapped
            .as_str()
            .nfc()
            .try_fold(0_usize, |length, character| {
                length.checked_add(character.len_utf8())
            })
            .ok_or(SecretError::InvalidPasswordProfile)?;
        if normalized_length > MAX_PASSWORD_UTF8_BYTES {
            return Err(SecretError::InvalidPasswordProfile);
        }
        let mut normalized = Zeroizing::new(String::with_capacity(normalized_length));
        let normalized_capacity = normalized.capacity();
        normalized.extend(mapped.as_str().nfc());
        if normalized.len() != normalized_length || normalized.capacity() != normalized_capacity {
            return Err(SecretError::CryptographicFailure);
        }
        let scalar_count = normalized.chars().count();
        let valid_scalars = normalized.chars().all(is_allowed_scalar);

        if scalar_count < MIN_PASSWORD_SCALARS || !valid_scalars {
            return Err(SecretError::InvalidPasswordProfile);
        }

        let mut bytes = Zeroizing::new(Vec::with_capacity(normalized.len()));
        let bytes_capacity = bytes.capacity();
        bytes.extend_from_slice(normalized.as_bytes());
        if bytes.len() != normalized.len() || bytes.capacity() != bytes_capacity {
            return Err(SecretError::CryptographicFailure);
        }
        Ok(Self {
            normalized_utf8: bytes,
        })
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.normalized_utf8.as_slice()
    }
}

fn map_space(character: char) -> char {
    if matches!(
        character,
        '\u{00A0}' | '\u{1680}' | '\u{2000}'..='\u{200A}' | '\u{202F}' | '\u{205F}' | '\u{3000}'
    ) {
        ' '
    } else {
        character
    }
}

fn is_allowed_scalar(character: char) -> bool {
    !character.is_control()
        && !matches!(character, '\u{2028}' | '\u{2029}')
        && !is_noncharacter(character)
}

fn is_noncharacter(character: char) -> bool {
    let value = u32::from(character);
    (0xFDD0..=0xFDEF).contains(&value) || value & 0xFFFE == 0xFFFE
}

#[cfg(test)]
mod tests {
    use super::VaultPassword;
    use crate::SecretError;

    #[test]
    fn profile_maps_unicode_space_and_normalizes_nfc() -> Result<(), SecretError> {
        let decomposed = VaultPassword::new("long-password-e\u{301}\u{00A0}value")?;
        let composed = VaultPassword::new("long-password-é value")?;
        assert_eq!(decomposed.as_bytes(), composed.as_bytes());
        Ok(())
    }

    #[test]
    fn profile_preserves_case() -> Result<(), SecretError> {
        let lower = VaultPassword::new("long-password-value")?;
        let upper = VaultPassword::new("Long-password-value")?;
        assert_ne!(lower.as_bytes(), upper.as_bytes());
        Ok(())
    }

    #[test]
    fn profile_rejects_short_control_and_oversized_values() {
        assert_eq!(
            VaultPassword::new("too-short").err(),
            Some(SecretError::InvalidPasswordProfile)
        );
        assert_eq!(
            VaultPassword::new("long-enough\u{0007}-password").err(),
            Some(SecretError::InvalidPasswordProfile)
        );
        assert_eq!(
            VaultPassword::new("long-enough\u{2028}password").err(),
            Some(SecretError::InvalidPasswordProfile)
        );
        let oversized = "x".repeat(1_025);
        assert_eq!(
            VaultPassword::new(&oversized).err(),
            Some(SecretError::InvalidPasswordProfile)
        );
    }
}
