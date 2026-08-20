use thiserror::Error;

/// Errors produced before or after vault authentication.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum SecretError {
    /// Password does not satisfy the fixed wallet password profile.
    #[error("password does not satisfy the vault password profile")]
    InvalidPasswordProfile,
    /// Mnemonic entropy strength or checksum is invalid.
    #[error("invalid BIP-39 mnemonic material")]
    InvalidMnemonic,
    /// A private key is not a valid secp256k1 scalar.
    #[error("invalid secp256k1 private key")]
    InvalidPrivateKey,
    /// A derivation path is malformed or outside supported bounds.
    #[error("invalid derivation path")]
    InvalidDerivationPath,
    /// No valid child exists in the supported account-index range.
    #[error("derivation index space exhausted")]
    DerivationExhausted,
    /// Cryptographic randomness was unavailable.
    #[error("operating system randomness unavailable")]
    RandomnessUnavailable,
    /// A fixed cryptographic primitive rejected its fixed parameters.
    #[error("cryptographic primitive failed")]
    CryptographicFailure,
    /// Vault contents exceed their strict format bounds.
    #[error("vault content exceeds supported bounds")]
    BoundsExceeded,
    /// Vault payload is internally malformed.
    #[error("vault payload is invalid")]
    InvalidPayload,
}

/// Public errors returned while opening an encrypted vault.
///
/// A wrong password and ciphertext/header-AAD integrity failure intentionally
/// collapse to the same `AuthenticationFailed` variant.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum VaultOpenError {
    /// The unauthenticated envelope is structurally unsupported or malformed.
    #[error("vault envelope is invalid or unsupported")]
    InvalidEnvelope,
    /// Password or authenticated data did not authenticate.
    #[error("vault authentication failed")]
    AuthenticationFailed,
    /// Authenticated plaintext did not decode as the declared payload schema.
    #[error("authenticated vault payload is invalid")]
    InvalidPayload,
    /// Fixed cryptographic processing failed for a non-authentication reason.
    #[error("vault cryptographic processing failed")]
    CryptographicFailure,
}
